/*
 *    Copyright (C) 2012 10gen Inc.
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
 *    must comply with the GNU Affero General Public License in all respects
 *    for all of the code used other than as permitted herein. If you modify
 *    file(s) with this exception, you may extend this exception to your
 *    version of the file(s), but you are not obligated to do so. If you do not
 *    wish to do so, delete this exception statement from your version. If you
 *    delete this exception statement from all source files in the program,
 *    then also delete it in the license file.
 */

/**
 * Should NOT be included by other header files.  Include only in source files.
 */

#pragma once

#include "mongo/base/status.h"
#include "mongo/platform/unordered_map.h"
#include "mongo/util/fail_point.h"

namespace mongo {
/**
 * Class for storing FailPoint instances.
 */
class FailPointRegistry {
public:
    FailPointRegistry();

    /**
     * Adds a new fail point to this registry. Duplicate names are not allowed.
     *
     * @return the status code under these circumstances:
     *     OK - if successful.
     *     DuplicateKey - if the given name already exists in this registry.
     *     CannotMutateObject - if this registry is already frozen.
     */
    Status addFailPoint(const std::string& name, FailPoint* failPoint);

    /**
     * @return the fail point object registered. Returns NULL if it was not registered.
     */
    FailPoint* getFailPoint(const std::string& name) const;

    /**
     * Freezes this registry from being modified.
     */
    void freeze();

    /**
     * Creates a new FailPointServerParameter for each failpoint in the registry. This allows the
     * failpoint to be set on the command line via --setParameter, but is only allowed when
     * running with '--setParameter enableTestCommands=1'.
     */
    void registerAllFailPointsAsServerParameters();

private:
    bool _frozen;
    unordered_map<std::string, FailPoint*> _fpMap;
};
}
