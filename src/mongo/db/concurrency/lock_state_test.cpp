/**
 *    Copyright (C) 2014 MongoDB Inc.
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

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kDefault

#include "mongo/platform/basic.h"

#include <algorithm>
#include <string>
#include <vector>

#include "mongo/config.h"
#include "mongo/db/concurrency/lock_manager_test_help.h"
#include "mongo/db/concurrency/locker.h"
#include "mongo/unittest/unittest.h"
#include "mongo/util/log.h"
#include "mongo/util/timer.h"

namespace mongo {

TEST(LockerImpl, LockNoConflict) {
    const ResourceId resId(RESOURCE_COLLECTION, "TestDB.collection"_sd);

    MMAPV1LockerImpl locker;
    locker.lockGlobal(MODE_IX);

    ASSERT(LOCK_OK == locker.lock(resId, MODE_X));

    ASSERT(locker.isLockHeldForMode(resId, MODE_X));
    ASSERT(locker.isLockHeldForMode(resId, MODE_S));

    ASSERT(locker.unlock(resId));

    ASSERT(locker.isLockHeldForMode(resId, MODE_NONE));

    locker.unlockGlobal();
}

TEST(LockerImpl, ReLockNoConflict) {
    const ResourceId resId(RESOURCE_COLLECTION, "TestDB.collection"_sd);

    MMAPV1LockerImpl locker;
    locker.lockGlobal(MODE_IX);

    ASSERT(LOCK_OK == locker.lock(resId, MODE_S));
    ASSERT(LOCK_OK == locker.lock(resId, MODE_X));

    ASSERT(!locker.unlock(resId));
    ASSERT(locker.isLockHeldForMode(resId, MODE_X));

    ASSERT(locker.unlock(resId));
    ASSERT(locker.isLockHeldForMode(resId, MODE_NONE));

    ASSERT(locker.unlockGlobal());
}

TEST(LockerImpl, ConflictWithTimeout) {
    const ResourceId resId(RESOURCE_COLLECTION, "TestDB.collection"_sd);

    DefaultLockerImpl locker1;
    ASSERT(LOCK_OK == locker1.lockGlobal(MODE_IX));
    ASSERT(LOCK_OK == locker1.lock(resId, MODE_X));

    DefaultLockerImpl locker2;
    ASSERT(LOCK_OK == locker2.lockGlobal(MODE_IX));
    ASSERT(LOCK_TIMEOUT == locker2.lock(resId, MODE_S, Milliseconds(0)));

    ASSERT(locker2.getLockMode(resId) == MODE_NONE);

    ASSERT(locker1.unlock(resId));

    ASSERT(locker1.unlockGlobal());
    ASSERT(locker2.unlockGlobal());
}

TEST(LockerImpl, ConflictUpgradeWithTimeout) {
    const ResourceId resId(RESOURCE_COLLECTION, "TestDB.collection"_sd);

    DefaultLockerImpl locker1;
    ASSERT(LOCK_OK == locker1.lockGlobal(MODE_IS));
    ASSERT(LOCK_OK == locker1.lock(resId, MODE_S));

    DefaultLockerImpl locker2;
    ASSERT(LOCK_OK == locker2.lockGlobal(MODE_IS));
    ASSERT(LOCK_OK == locker2.lock(resId, MODE_S));

    // Try upgrading locker 1, which should block and timeout
    ASSERT(LOCK_TIMEOUT == locker1.lock(resId, MODE_X, Milliseconds(1)));

    locker1.unlockGlobal();
    locker2.unlockGlobal();
}


TEST(LockerImpl, ReadTransaction) {
    DefaultLockerImpl locker;

    locker.lockGlobal(MODE_IS);
    locker.unlockGlobal();

    locker.lockGlobal(MODE_IX);
    locker.unlockGlobal();

    locker.lockGlobal(MODE_IX);
    locker.lockGlobal(MODE_IS);
    locker.unlockGlobal();
    locker.unlockGlobal();
}

/**
 * Test that saveMMAPV1LockerImpl works by examining the output.
 */
TEST(LockerImpl, saveAndRestoreGlobal) {
    Locker::LockSnapshot lockInfo;

    DefaultLockerImpl locker;

    // No lock requests made, no locks held.
    locker.saveLockStateAndUnlock(&lockInfo);
    ASSERT_EQUALS(0U, lockInfo.locks.size());

    // Lock the global lock, but just once.
    locker.lockGlobal(MODE_IX);

    // We've locked the global lock.  This should be reflected in the lockInfo.
    locker.saveLockStateAndUnlock(&lockInfo);
    ASSERT(!locker.isLocked());
    ASSERT_EQUALS(MODE_IX, lockInfo.globalMode);

    // Restore the lock(s) we had.
    locker.restoreLockState(lockInfo);

    ASSERT(locker.isLocked());
    ASSERT(locker.unlockGlobal());
}

/**
 * Test that we don't unlock when we have the global lock more than once.
 */
TEST(LockerImpl, saveAndRestoreGlobalAcquiredTwice) {
    Locker::LockSnapshot lockInfo;

    DefaultLockerImpl locker;

    // No lock requests made, no locks held.
    locker.saveLockStateAndUnlock(&lockInfo);
    ASSERT_EQUALS(0U, lockInfo.locks.size());

    // Lock the global lock.
    locker.lockGlobal(MODE_IX);
    locker.lockGlobal(MODE_IX);

    // This shouldn't actually unlock as we're in a nested scope.
    ASSERT(!locker.saveLockStateAndUnlock(&lockInfo));

    ASSERT(locker.isLocked());

    // We must unlockGlobal twice.
    ASSERT(!locker.unlockGlobal());
    ASSERT(locker.unlockGlobal());
}

/**
 * Tests that restoreMMAPV1LockerImpl works by locking a db and collection and saving + restoring.
 */
TEST(LockerImpl, saveAndRestoreDBAndCollection) {
    Locker::LockSnapshot lockInfo;

    DefaultLockerImpl locker;

    const ResourceId resIdDatabase(RESOURCE_DATABASE, "TestDB"_sd);
    const ResourceId resIdCollection(RESOURCE_COLLECTION, "TestDB.collection"_sd);

    // Lock some stuff.
    locker.lockGlobal(MODE_IX);
    ASSERT_EQUALS(LOCK_OK, locker.lock(resIdDatabase, MODE_IX));
    ASSERT_EQUALS(LOCK_OK, locker.lock(resIdCollection, MODE_X));
    locker.saveLockStateAndUnlock(&lockInfo);

    // Things shouldn't be locked anymore.
    ASSERT_EQUALS(MODE_NONE, locker.getLockMode(resIdDatabase));
    ASSERT_EQUALS(MODE_NONE, locker.getLockMode(resIdCollection));

    // Restore lock state.
    locker.restoreLockState(lockInfo);

    // Make sure things were re-locked.
    ASSERT_EQUALS(MODE_IX, locker.getLockMode(resIdDatabase));
    ASSERT_EQUALS(MODE_X, locker.getLockMode(resIdCollection));

    ASSERT(locker.unlockGlobal());
}

TEST(LockerImpl, DefaultLocker) {
    const ResourceId resId(RESOURCE_DATABASE, "TestDB"_sd);

    DefaultLockerImpl locker;
    ASSERT_EQUALS(LOCK_OK, locker.lockGlobal(MODE_IX));
    ASSERT_EQUALS(LOCK_OK, locker.lock(resId, MODE_X));

    // Make sure the flush lock IS NOT held
    Locker::LockerInfo info;
    locker.getLockerInfo(&info);
    ASSERT(!info.waitingResource.isValid());
    ASSERT_EQUALS(2U, info.locks.size());
    ASSERT_EQUALS(RESOURCE_GLOBAL, info.locks[0].resourceId.getType());
    ASSERT_EQUALS(resId, info.locks[1].resourceId);

    ASSERT(locker.unlockGlobal());
}

TEST(LockerImpl, MMAPV1Locker) {
    const ResourceId resId(RESOURCE_DATABASE, "TestDB"_sd);

    MMAPV1LockerImpl locker;
    ASSERT_EQUALS(LOCK_OK, locker.lockGlobal(MODE_IX));
    ASSERT_EQUALS(LOCK_OK, locker.lock(resId, MODE_X));

    // Make sure the flush lock IS held
    Locker::LockerInfo info;
    locker.getLockerInfo(&info);
    ASSERT(!info.waitingResource.isValid());
    ASSERT_EQUALS(3U, info.locks.size());
    ASSERT_EQUALS(RESOURCE_GLOBAL, info.locks[0].resourceId.getType());
    ASSERT_EQUALS(RESOURCE_MMAPV1_FLUSH, info.locks[1].resourceId.getType());
    ASSERT_EQUALS(resId, info.locks[2].resourceId);

    ASSERT(locker.unlockGlobal());
}

TEST(LockerImpl, CanceledDeadlockUnblocks) {
    const ResourceId db1(RESOURCE_DATABASE, "db1"_sd);
    const ResourceId db2(RESOURCE_DATABASE, "db2"_sd);

    DefaultLockerImpl locker1;
    DefaultLockerImpl locker2;
    DefaultLockerImpl locker3;

    ASSERT(LOCK_OK == locker1.lockGlobal(MODE_IX));
    ASSERT(LOCK_OK == locker1.lock(db1, MODE_S));

    ASSERT(LOCK_OK == locker2.lockGlobal(MODE_IX));
    ASSERT(LOCK_OK == locker2.lock(db2, MODE_X));

    // Set up locker1 and locker2 for deadlock
    ASSERT(LOCK_WAITING == locker1.lockBegin(db2, MODE_X));
    ASSERT(LOCK_WAITING == locker2.lockBegin(db1, MODE_X));

    // Locker3 blocks behind locker 2
    ASSERT(LOCK_OK == locker3.lockGlobal(MODE_IX));
    ASSERT(LOCK_WAITING == locker3.lockBegin(db1, MODE_S));

    // Detect deadlock, canceling our request
    ASSERT(LOCK_DEADLOCK ==
           locker2.lockComplete(db1, MODE_X, Milliseconds(1), /*checkDeadlock*/ true));

    // Now locker3 must be able to complete its request
    ASSERT(LOCK_OK == locker3.lockComplete(db1, MODE_S, Milliseconds(1), /*checkDeadlock*/ false));

    // Locker1 still can't complete its request
    ASSERT(LOCK_TIMEOUT == locker1.lockComplete(db2, MODE_X, Milliseconds(1), false));

    // Check ownership for db1
    ASSERT(locker1.getLockMode(db1) == MODE_S);
    ASSERT(locker2.getLockMode(db1) == MODE_NONE);
    ASSERT(locker3.getLockMode(db1) == MODE_S);

    // Check ownership for db2
    ASSERT(locker1.getLockMode(db2) == MODE_NONE);
    ASSERT(locker2.getLockMode(db2) == MODE_X);
    ASSERT(locker3.getLockMode(db2) == MODE_NONE);

    ASSERT(locker1.unlockGlobal());
    ASSERT(locker2.unlockGlobal());
    ASSERT(locker3.unlockGlobal());
}

namespace {
/**
 * Helper function to determine if 'lockerInfo' contains a lock with ResourceId 'resourceId' and
 * lock mode 'mode' within 'lockerInfo.locks'.
 */
bool lockerInfoContainsLock(const Locker::LockerInfo& lockerInfo,
                            const ResourceId& resourceId,
                            const LockMode& mode) {
    return (1U == std::count_if(lockerInfo.locks.begin(),
                                lockerInfo.locks.end(),
                                [&resourceId, &mode](const Locker::OneLock& lock) {
                                    return lock.resourceId == resourceId && lock.mode == mode;
                                }));
}
}  // namespace

TEST(LockerImpl, GetLockerInfoShouldReportHeldLocks) {
    const ResourceId globalId(RESOURCE_GLOBAL, ResourceId::SINGLETON_GLOBAL);
    const ResourceId dbId(RESOURCE_DATABASE, "TestDB"_sd);
    const ResourceId collectionId(RESOURCE_COLLECTION, "TestDB.collection"_sd);

    // Take an exclusive lock on the collection.
    DefaultLockerImpl locker;
    ASSERT_EQ(LOCK_OK, locker.lockGlobal(MODE_IX));
    ASSERT_EQ(LOCK_OK, locker.lock(dbId, MODE_IX));
    ASSERT_EQ(LOCK_OK, locker.lock(collectionId, MODE_X));

    // Assert it shows up in the output of getLockerInfo().
    Locker::LockerInfo lockerInfo;
    locker.getLockerInfo(&lockerInfo);

    ASSERT(lockerInfoContainsLock(lockerInfo, globalId, MODE_IX));
    ASSERT(lockerInfoContainsLock(lockerInfo, dbId, MODE_IX));
    ASSERT(lockerInfoContainsLock(lockerInfo, collectionId, MODE_X));
    ASSERT_EQ(3U, lockerInfo.locks.size());

    ASSERT(locker.unlock(collectionId));
    ASSERT(locker.unlock(dbId));
    ASSERT(locker.unlockGlobal());
}

TEST(LockerImpl, GetLockerInfoShouldReportPendingLocks) {
    const ResourceId globalId(RESOURCE_GLOBAL, ResourceId::SINGLETON_GLOBAL);
    const ResourceId dbId(RESOURCE_DATABASE, "TestDB"_sd);
    const ResourceId collectionId(RESOURCE_COLLECTION, "TestDB.collection"_sd);

    // Take an exclusive lock on the collection.
    DefaultLockerImpl successfulLocker;
    ASSERT_EQ(LOCK_OK, successfulLocker.lockGlobal(MODE_IX));
    ASSERT_EQ(LOCK_OK, successfulLocker.lock(dbId, MODE_IX));
    ASSERT_EQ(LOCK_OK, successfulLocker.lock(collectionId, MODE_X));

    // Now attempt to get conflicting locks.
    DefaultLockerImpl conflictingLocker;
    ASSERT_EQ(LOCK_OK, conflictingLocker.lockGlobal(MODE_IS));
    ASSERT_EQ(LOCK_OK, conflictingLocker.lock(dbId, MODE_IS));
    ASSERT_EQ(LOCK_WAITING, conflictingLocker.lockBegin(collectionId, MODE_IS));

    // Assert the held locks show up in the output of getLockerInfo().
    Locker::LockerInfo lockerInfo;
    conflictingLocker.getLockerInfo(&lockerInfo);
    ASSERT(lockerInfoContainsLock(lockerInfo, globalId, MODE_IS));
    ASSERT(lockerInfoContainsLock(lockerInfo, dbId, MODE_IS));
    ASSERT(lockerInfoContainsLock(lockerInfo, collectionId, MODE_IS));
    ASSERT_EQ(3U, lockerInfo.locks.size());

    // Assert it reports that it is waiting for the collection lock.
    ASSERT_EQ(collectionId, lockerInfo.waitingResource);

    // Make sure it no longer reports waiting once unlocked.
    ASSERT(successfulLocker.unlock(collectionId));
    ASSERT(successfulLocker.unlock(dbId));
    ASSERT(successfulLocker.unlockGlobal());

    const Milliseconds timeout = Milliseconds(0);
    const bool checkDeadlock = false;
    ASSERT_EQ(LOCK_OK,
              conflictingLocker.lockComplete(collectionId, MODE_IS, timeout, checkDeadlock));

    conflictingLocker.getLockerInfo(&lockerInfo);
    ASSERT_FALSE(lockerInfo.waitingResource.isValid());

    ASSERT(conflictingLocker.unlock(collectionId));
    ASSERT(conflictingLocker.unlock(dbId));
    ASSERT(conflictingLocker.unlockGlobal());
}

}  // namespace mongo
