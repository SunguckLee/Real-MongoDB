/**
 *    Copyright (C) 2013 10gen Inc.
 *
 *    This program is free software: you can redistribute it and/or  modify
 *    it under the terms of the GNU Affero General Public License, version 3,
 *    as published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU Affero General Public License for more details.
 *
 *    You should have received a copy of the GNU Affero General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the GNU Affero General Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#include "mongo/platform/basic.h"

#include <string>

#include "mongo/db/range_deleter.h"
#include "mongo/db/range_deleter_mock_env.h"
#include "mongo/db/repl/repl_settings.h"
#include "mongo/db/repl/replication_coordinator_mock.h"
#include "mongo/db/service_context_noop.h"
#include "mongo/stdx/functional.h"
#include "mongo/stdx/future.h"
#include "mongo/stdx/memory.h"
#include "mongo/stdx/thread.h"
#include "mongo/unittest/unittest.h"
#include "mongo/util/scopeguard.h"

namespace mongo {
namespace {

using std::string;

// The range deleter cursor close wait interval increases exponentially from 5 milliseconds to an
// upper bound of 500 msec. Three seconds should be enough time for changes in the cursors set to be
// noticed.
const Seconds MAX_IMMEDIATE_DELETE_WAIT(3);

const mongo::repl::ReplSettings replSettings = {};

class RangeDeleterTestFixture : public unittest::Test {
public:
    RangeDeleterTestFixture()
        : _client(_serviceContext.makeClient("TestClient")),
          _opCtx(_client->makeOperationContext()) {}

protected:
    OperationContext* opCtx() const {
        return _opCtx.get();
    }

private:
    ServiceContextNoop _serviceContext;
    ServiceContext::UniqueClient _client;
    ServiceContext::UniqueOperationContext _opCtx;
};

using QueuedDelete = RangeDeleterTestFixture;

// Should not be able to queue deletes if deleter workers were not started.
TEST_F(QueuedDelete, CantAfterStop) {
    RangeDeleterMockEnv* env = new RangeDeleterMockEnv();
    RangeDeleter deleter(env);

    std::unique_ptr<mongo::repl::ReplicationCoordinatorMock> mock(
        new mongo::repl::ReplicationCoordinatorMock(replSettings));

    mongo::repl::ReplicationCoordinator::set(mongo::getGlobalServiceContext(), std::move(mock));

    deleter.startWorkers();
    deleter.stopWorkers();

    string errMsg;
    ASSERT_FALSE(
        deleter.queueDelete(opCtx(),
                            RangeDeleterOptions(KeyRange(
                                "test.user", BSON("x" << 120), BSON("x" << 200), BSON("x" << 1))),
                            NULL /* notifier not needed */,
                            &errMsg));
    ASSERT_FALSE(errMsg.empty());
    ASSERT_FALSE(env->deleteOccured());
}

// Should not start delete if the set of cursors that were open when the
// delete was queued is still open.
TEST_F(QueuedDelete, ShouldWaitCursor) {
    const string ns("test.user");

    RangeDeleterMockEnv* env = new RangeDeleterMockEnv();
    RangeDeleter deleter(env);

    std::unique_ptr<mongo::repl::ReplicationCoordinatorMock> mock(
        new mongo::repl::ReplicationCoordinatorMock(replSettings));

    mongo::repl::ReplicationCoordinator::set(mongo::getGlobalServiceContext(), std::move(mock));

    deleter.startWorkers();

    env->addCursorId(ns, 345);

    Notification<void> doneSignal;
    RangeDeleterOptions deleterOptions(
        KeyRange(ns, BSON("x" << 0), BSON("x" << 10), BSON("x" << 1)));
    deleterOptions.waitForOpenCursors = true;

    ASSERT_TRUE(
        deleter.queueDelete(opCtx(), deleterOptions, &doneSignal, NULL /* errMsg not needed */));

    env->waitForNthGetCursor(1u);

    ASSERT_EQUALS(1U, deleter.getPendingDeletes());
    ASSERT_FALSE(env->deleteOccured());

    // Set the open cursors to a totally different sets of cursorIDs.
    env->addCursorId(ns, 200);
    env->removeCursorId(ns, 345);

    doneSignal.get(opCtx());

    ASSERT_TRUE(env->deleteOccured());
    const DeletedRange deletedChunk(env->getLastDelete());

    ASSERT_EQUALS(ns, deletedChunk.ns);
    ASSERT_BSONOBJ_EQ(deletedChunk.min, BSON("x" << 0));
    ASSERT_BSONOBJ_EQ(deletedChunk.max, BSON("x" << 10));

    deleter.stopWorkers();
}

// Should terminate when stop is requested.
TEST_F(QueuedDelete, StopWhileWaitingCursor) {
    const string ns("test.user");

    RangeDeleterMockEnv* env = new RangeDeleterMockEnv();
    RangeDeleter deleter(env);

    std::unique_ptr<mongo::repl::ReplicationCoordinatorMock> mock(
        new mongo::repl::ReplicationCoordinatorMock(replSettings));

    mongo::repl::ReplicationCoordinator::set(mongo::getGlobalServiceContext(), std::move(mock));

    deleter.startWorkers();

    env->addCursorId(ns, 345);

    Notification<void> doneSignal;
    RangeDeleterOptions deleterOptions(
        KeyRange(ns, BSON("x" << 0), BSON("x" << 10), BSON("x" << 1)));
    deleterOptions.waitForOpenCursors = true;
    ASSERT_TRUE(
        deleter.queueDelete(opCtx(), deleterOptions, &doneSignal, NULL /* errMsg not needed */));


    env->waitForNthGetCursor(1u);

    deleter.stopWorkers();
    ASSERT_FALSE(env->deleteOccured());
}

using ImmediateDelete = RangeDeleterTestFixture;

// Should not start delete if the set of cursors that were open when the deleteNow method is called
// is still open.
TEST_F(ImmediateDelete, ShouldWaitCursor) {
    const string ns("test.user");

    RangeDeleterMockEnv* env = new RangeDeleterMockEnv();
    RangeDeleter deleter(env);

    std::unique_ptr<mongo::repl::ReplicationCoordinatorMock> mock(
        new mongo::repl::ReplicationCoordinatorMock(replSettings));

    mongo::repl::ReplicationCoordinator::set(mongo::getGlobalServiceContext(), std::move(mock));

    deleter.startWorkers();

    env->addCursorId(ns, 345);

    string errMsg;
    RangeDeleterOptions deleterOption(
        KeyRange(ns, BSON("x" << 0), BSON("x" << 10), BSON("x" << 1)));
    deleterOption.waitForOpenCursors = true;

    stdx::packaged_task<bool()> deleterTask(
        [&] { return deleter.deleteNow(opCtx(), deleterOption, &errMsg); });
    stdx::future<bool> deleterFuture = deleterTask.get_future();
    stdx::thread deleterThread(std::move(deleterTask));

    auto guard = MakeGuard([&] {
        deleter.stopWorkers();
        deleterThread.join();
    });

    env->waitForNthGetCursor(1u);

    // Note: immediate deletes has no pending state, it goes directly to inProgress
    // even while waiting for cursors.
    ASSERT_EQUALS(1U, deleter.getDeletesInProgress());

    ASSERT_FALSE(env->deleteOccured());

    // Set the open cursors to a totally different sets of cursorIDs.
    env->addCursorId(ns, 200);
    env->removeCursorId(ns, 345);

    ASSERT_TRUE(stdx::future_status::ready ==
                deleterFuture.wait_for(MAX_IMMEDIATE_DELETE_WAIT.toSystemDuration()));
    ASSERT_TRUE(deleterFuture.get());
    ASSERT_TRUE(env->deleteOccured());

    const DeletedRange deletedChunk(env->getLastDelete());

    ASSERT_EQUALS(ns, deletedChunk.ns);
    ASSERT_BSONOBJ_EQ(deletedChunk.min, BSON("x" << 0));
    ASSERT_BSONOBJ_EQ(deletedChunk.max, BSON("x" << 10));
    ASSERT_BSONOBJ_EQ(deletedChunk.shardKeyPattern, BSON("x" << 1));
}

// Should terminate when stop is requested.
TEST_F(ImmediateDelete, StopWhileWaitingCursor) {
    const string ns("test.user");

    RangeDeleterMockEnv* env = new RangeDeleterMockEnv();
    RangeDeleter deleter(env);

    std::unique_ptr<mongo::repl::ReplicationCoordinatorMock> mock(
        new mongo::repl::ReplicationCoordinatorMock(replSettings));

    mongo::repl::ReplicationCoordinator::set(mongo::getGlobalServiceContext(), std::move(mock));

    deleter.startWorkers();

    env->addCursorId(ns, 345);

    string errMsg;
    RangeDeleterOptions deleterOption(
        KeyRange(ns, BSON("x" << 0), BSON("x" << 10), BSON("x" << 1)));
    deleterOption.waitForOpenCursors = true;

    stdx::packaged_task<bool()> deleterTask(
        [&] { return deleter.deleteNow(opCtx(), deleterOption, &errMsg); });
    stdx::future<bool> deleterFuture = deleterTask.get_future();
    stdx::thread deleterThread(std::move(deleterTask));

    auto join_thread_guard = MakeGuard([&] { deleterThread.join(); });
    auto stop_deleter_guard = MakeGuard([&] { deleter.stopWorkers(); });

    env->waitForNthGetCursor(1u);

    // Note: immediate deletes has no pending state, it goes directly to inProgress
    // even while waiting for cursors.
    ASSERT_EQUALS(1U, deleter.getDeletesInProgress());

    ASSERT_FALSE(env->deleteOccured());

    stop_deleter_guard.Execute();

    ASSERT_TRUE(stdx::future_status::ready ==
                deleterFuture.wait_for(MAX_IMMEDIATE_DELETE_WAIT.toSystemDuration()));
    ASSERT_FALSE(deleterFuture.get());
    ASSERT_FALSE(env->deleteOccured());
}

using MixedDeletes = RangeDeleterTestFixture;

// Tests the interaction of multiple deletes queued with different states. Starts by adding a new
// delete task, waits for the worker to work on it, and then adds 2 more task, one of which is ready
// to be deleted, while the other one is waiting for an open cursor. The test then makes sure that
// the deletes are performed in the right order.
TEST_F(MixedDeletes, MultipleDeletes) {
    const string blockedNS("foo.bar");
    const string ns("test.user");

    RangeDeleterMockEnv* env = new RangeDeleterMockEnv();
    RangeDeleter deleter(env);

    std::unique_ptr<mongo::repl::ReplicationCoordinatorMock> mock(
        new mongo::repl::ReplicationCoordinatorMock(replSettings));

    mongo::repl::ReplicationCoordinator::set(mongo::getGlobalServiceContext(), std::move(mock));

    deleter.startWorkers();

    env->addCursorId(blockedNS, 345);
    env->pauseDeletes();

    Notification<void> doneSignal1;
    RangeDeleterOptions deleterOption1(
        KeyRange(ns, BSON("x" << 10), BSON("x" << 20), BSON("x" << 1)));
    deleterOption1.waitForOpenCursors = true;
    ASSERT_TRUE(
        deleter.queueDelete(opCtx(), deleterOption1, &doneSignal1, NULL /* don't care errMsg */));

    env->waitForNthPausedDelete(1u);

    // Make sure that the delete is already in progress before proceeding.
    ASSERT_EQUALS(1U, deleter.getDeletesInProgress());

    Notification<void> doneSignal2;
    RangeDeleterOptions deleterOption2(
        KeyRange(blockedNS, BSON("x" << 20), BSON("x" << 30), BSON("x" << 1)));
    deleterOption2.waitForOpenCursors = true;
    ASSERT_TRUE(
        deleter.queueDelete(opCtx(), deleterOption2, &doneSignal2, NULL /* don't care errMsg */));

    Notification<void> doneSignal3;
    RangeDeleterOptions deleterOption3(
        KeyRange(ns, BSON("x" << 30), BSON("x" << 40), BSON("x" << 1)));
    deleterOption3.waitForOpenCursors = true;
    ASSERT_TRUE(
        deleter.queueDelete(opCtx(), deleterOption3, &doneSignal3, NULL /* don't care errMsg */));

    // Now, the setup is:
    // { x: 10 } => { x: 20 } in progress.
    // { x: 20 } => { x: 30 } waiting for cursor id 345.
    // { x: 30 } => { x: 40 } waiting to be picked up by worker.

    // Make sure that the current state matches the setup.
    ASSERT_EQUALS(3U, deleter.getTotalDeletes());
    ASSERT_EQUALS(2U, deleter.getPendingDeletes());
    ASSERT_EQUALS(1U, deleter.getDeletesInProgress());

    // Let the first delete proceed.
    env->resumeOneDelete();
    doneSignal1.get(opCtx());

    ASSERT_TRUE(env->deleteOccured());

    // { x: 10 } => { x: 20 } should be the first one since it is already in
    // progress before the others are queued.
    DeletedRange deleted1(env->getLastDelete());

    ASSERT_EQUALS(ns, deleted1.ns);
    ASSERT_BSONOBJ_EQ(deleted1.min, BSON("x" << 10));
    ASSERT_BSONOBJ_EQ(deleted1.max, BSON("x" << 20));
    ASSERT_BSONOBJ_EQ(deleted1.shardKeyPattern, BSON("x" << 1));

    // Let the second delete proceed.
    env->resumeOneDelete();
    doneSignal3.get(opCtx());

    DeletedRange deleted2(env->getLastDelete());

    // { x: 30 } => { x: 40 } should be next since there are still
    // cursors open for blockedNS.

    ASSERT_EQUALS(ns, deleted2.ns);
    ASSERT_BSONOBJ_EQ(deleted2.min, BSON("x" << 30));
    ASSERT_BSONOBJ_EQ(deleted2.max, BSON("x" << 40));
    ASSERT_BSONOBJ_EQ(deleted2.shardKeyPattern, BSON("x" << 1));

    env->removeCursorId(blockedNS, 345);
    // Let the last delete proceed.
    env->resumeOneDelete();
    doneSignal2.get(opCtx());

    DeletedRange deleted3(env->getLastDelete());

    ASSERT_EQUALS(blockedNS, deleted3.ns);
    ASSERT_BSONOBJ_EQ(deleted3.min, BSON("x" << 20));
    ASSERT_BSONOBJ_EQ(deleted3.max, BSON("x" << 30));
    ASSERT_BSONOBJ_EQ(deleted3.shardKeyPattern, BSON("x" << 1));

    deleter.stopWorkers();
}

}  // unnamed namespace
}  // namespace mongo
