/**
 *    Copyright (C) 2016 MongoDB Inc.
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


#pragma once

#include "mongo/platform/basic.h"

#include "mongo/base/status.h"
#include "mongo/base/status_with.h"
#include "mongo/bson/bsonobj.h"
#include "mongo/bson/timestamp.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/repl/databases_cloner.h"
#include "mongo/db/repl/optime.h"
#include "mongo/db/repl/replication_executor.h"
#include "mongo/util/net/hostandport.h"

namespace mongo {
namespace repl {

/**
 * Holder of state for initial sync (InitialSyncer).
 */
struct InitialSyncState {
    InitialSyncState(std::unique_ptr<DatabasesCloner> cloner) : dbsCloner(std::move(cloner)){};

    std::unique_ptr<DatabasesCloner>
        dbsCloner;             // Cloner for all databases included in initial sync.
    Timestamp beginTimestamp;  // Timestamp from the latest entry in oplog when started.
    Timestamp stopTimestamp;   // Referred to as minvalid, or the place we can transition states.
    Timer timer;               // Timer for timing how long each initial sync attempt takes.
    size_t fetchedMissingDocs = 0;
    size_t appliedOps = 0;
};

}  // namespace repl
}  // namespace mongo
