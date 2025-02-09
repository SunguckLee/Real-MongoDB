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

#pragma once

#include "mongo/db/storage/mmap_v1/diskloc.h"
#include "mongo/db/storage/record_store.h"

namespace mongo {

class SimpleRecordStoreV1;

/**
 * This class iterates over a non-capped collection identified by 'ns'.
 * The collection must exist when the constructor is called.
 *
 * If start is not DiskLoc(), the iteration begins at that DiskLoc.
 */
class SimpleRecordStoreV1Iterator final : public SeekableRecordCursor {
public:
    SimpleRecordStoreV1Iterator(OperationContext* txn,
                                const SimpleRecordStoreV1* records,
                                bool forward);

    boost::optional<Record> next() final;
    boost::optional<Record> seekExact(const RecordId& id) final;
    void save() final;
    bool restore() final;
    void detachFromOperationContext() final {
        _txn = nullptr;
    }
    void reattachToOperationContext(OperationContext* txn) final {
        _txn = txn;
    }
    void invalidate(OperationContext* txn, const RecordId& dl) final;
    std::unique_ptr<RecordFetcher> fetcherForNext() const final;
    std::unique_ptr<RecordFetcher> fetcherForId(const RecordId& id) const final;

private:
    void advance();
    bool isEOF() {
        return _curr.isNull();
    }

    // for getNext, not owned
    OperationContext* _txn;

    // The result returned on the next call to getNext().
    DiskLoc _curr;
    const SimpleRecordStoreV1* const _recordStore;
    const bool _forward;
};

}  // namespace mongo
