/**
 *    Copyright (C) 2015 MongoDB Inc.
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

#include "mongo/base/disallow_copying.h"
#include "mongo/base/status_with.h"
#include "mongo/db/jsobj.h"

namespace mongo {

class NamespaceString;
class OperationContext;

namespace repl {

class OplogInterface;

/**
 * Interface for rollback-related operations on the sync source.
 */
class RollbackSource {
    MONGO_DISALLOW_COPYING(RollbackSource);

public:
    RollbackSource() = default;

    virtual ~RollbackSource() = default;

    /**
     * Returns remote oplog interface.
     * Read oplog entries with OplogInterface::makeIterator().
     */
    virtual const OplogInterface& getOplog() const = 0;

    /**
     * Returns rollback ID.
     */
    virtual int getRollbackId() const = 0;

    /**
     * Returns last operation in oplog.
     */
    virtual BSONObj getLastOperation() const = 0;

    /**
     * Fetch a single document from the sync source.
     */
    virtual BSONObj findOne(const NamespaceString& nss, const BSONObj& filter) const = 0;

    /**
     * Clones a single collection from the sync source.
     */
    virtual void copyCollectionFromRemote(OperationContext* txn,
                                          const NamespaceString& nss) const = 0;

    /**
     * Returns collection info.
     */
    virtual StatusWith<BSONObj> getCollectionInfo(const NamespaceString& nss) const = 0;
};

}  // namespace repl
}  // namespace mongo
