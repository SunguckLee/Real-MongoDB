/**
 *    Copyright (C) 2010-2014 MongoDB Inc.
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

#include <atomic>

#include "mongo/client/connection_string.h"
#include "mongo/db/query/explain_common.h"
#include "mongo/s/client/shard.h"

namespace mongo {

class DbMessage;
class NamespaceString;
class OperationContext;
class QueryRequest;

namespace rpc {
class ServerSelectionMetadata;
}  // namespace rpc

/**
 * Legacy interface for processing client read/write/cmd requests.
 */
class Strategy {
public:
    /**
     * Handles a legacy-style opQuery request and sends the response back on success or throws on
     * error.
     *
     * Must not be called with legacy '.$cmd' commands.
     */
    static void queryOp(OperationContext* txn, const NamespaceString& nss, DbMessage* dbm);

    /**
     * Handles a legacy-style getMore request and sends the response back on success (or cursor not
     * found) or throws on error.
     */
    static void getMore(OperationContext* txn, const NamespaceString& nss, DbMessage* dbm);

    /**
     * Handles a legacy-style killCursors request. Doesn't send any response on success or throws on
     * error.
     */
    static void killCursors(OperationContext* txn, DbMessage* dbm);

    /**
     * Handles a legacy-style write operation request and updates the last error state on the client
     * with the result from the operation. Doesn't send any response back and does not throw on
     * errors.
     */
    static void writeOp(OperationContext* txn, DbMessage* dbm);

    /**
     * Executes a legacy-style ($cmd namespace) command. Does not throw and returns the response
     * regardless of success or error.
     *
     * Catches StaleConfigException errors and retries the command automatically after refreshing
     * the metadata for the failing namespace.
     */
    static void clientCommandOp(OperationContext* txn, const NamespaceString& nss, DbMessage* dbm);

    /**
     * Helper to run an explain of a find operation on the shards. Fills 'out' with the result of
     * the of the explain command on success. On failure, returns a non-OK status and does not
     * modify 'out'.
     *
     * Used both if mongos receives an explain command and if it receives an OP_QUERY find with the
     * $explain modifier.
     */
    static Status explainFind(OperationContext* txn,
                              const BSONObj& findCommand,
                              const QueryRequest& qr,
                              ExplainCommon::Verbosity verbosity,
                              const rpc::ServerSelectionMetadata& serverSelectionMetadata,
                              BSONObjBuilder* out);

    struct CommandResult {
        ShardId shardTargetId;
        ConnectionString target;
        BSONObj result;
    };

    /**
     * Executes a command against a particular database, and targets the command based on a
     * collection in that database, according to 'targetingQuery' and 'targetingCollation'. If
     * 'targetingCollation' is empty, the collection default collation is used for targeting.
     *
     * This version should be used by internal commands when possible.
     *
     * TODO: Replace these methods and all other methods of command dispatch with a more general
     * command op framework.
     */
    static void commandOp(OperationContext* txn,
                          const std::string& db,
                          const BSONObj& command,
                          int options,
                          const std::string& versionedNS,
                          const BSONObj& targetingQuery,
                          const BSONObj& targetingCollation,
                          std::vector<CommandResult>* results);
};

}  // namespace mongo
