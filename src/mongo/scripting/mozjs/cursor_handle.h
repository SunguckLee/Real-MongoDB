/**
 * Copyright (C) 2015 MongoDB Inc.
 *
 * This program is free software: you can redistribute it and/or  modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, the copyright holders give permission to link the
 * code of portions of this program with the OpenSSL library under certain
 * conditions as described in each individual source file and distribute
 * linked combinations including the program with the OpenSSL library. You
 * must comply with the GNU Affero General Public License in all respects
 * for all of the code used other than as permitted herein. If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so. If you do not
 * wish to do so, delete this exception statement from your version. If you
 * delete this exception statement from all source files in the program,
 * then also delete it in the license file.
 */

#pragma once

#include "mongo/client/dbclientcursor.h"
#include "mongo/client/dbclientinterface.h"
#include "mongo/scripting/mozjs/wraptype.h"

namespace mongo {
namespace mozjs {

/**
 * Wraps a DBClientCursor in javascript.
 *
 * Note that the install is private, so this class should only be constructible from C++. Current
 * callers are all via the Mongo object.
 */
struct CursorHandleInfo : public BaseInfo {
    static void finalize(JSFreeOp* fop, JSObject* obj);

    struct Functions {
        MONGO_DECLARE_JS_FUNCTION(zeroCursorId);
    };

    static const JSFunctionSpec methods[2];

    static const char* const className;
    static const unsigned classFlags = JSCLASS_HAS_PRIVATE;
    static const InstallType installType = InstallType::Private;

    /**
     * We need this because the DBClientBase can go out of scope before all of its children (as
     * in global shutdown). So we have to manage object lifetimes in C++ land.
     */
    struct CursorTracker {
        CursorTracker(long long curId, std::shared_ptr<DBClientBase> client)
            : client(std::move(client)), cursorId(curId) {}

        std::shared_ptr<DBClientBase> client;
        long long cursorId;
    };
};

}  // namespace mozjs
}  // namespace mongo
