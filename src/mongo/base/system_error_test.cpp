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

#include "mongo/platform/basic.h"

#include <system_error>

#include "mongo/base/system_error.h"
#include "mongo/unittest/unittest.h"

namespace mongo {
namespace {

TEST(SystemError, Category) {
    ASSERT(make_error_code(ErrorCodes::AuthenticationFailed).category() == mongoErrorCategory());
    ASSERT(std::error_code(ErrorCodes::AlreadyInitialized, mongoErrorCategory()).category() ==
           mongoErrorCategory());
    ASSERT(make_error_condition(ErrorCodes::AuthenticationFailed).category() ==
           mongoErrorCategory());
    ASSERT(std::error_condition(ErrorCodes::AuthenticationFailed).category() ==
           mongoErrorCategory());
}

TEST(SystemError, Conversions) {
    ASSERT(make_error_code(ErrorCodes::AlreadyInitialized) == ErrorCodes::AlreadyInitialized);
    ASSERT(std::error_code(ErrorCodes::AlreadyInitialized, mongoErrorCategory()) ==
           ErrorCodes::AlreadyInitialized);
    ASSERT(make_error_condition(ErrorCodes::AlreadyInitialized) == ErrorCodes::AlreadyInitialized);
    ASSERT(std::error_condition(ErrorCodes::AlreadyInitialized) == ErrorCodes::AlreadyInitialized);
}

TEST(SystemError, Equivalence) {
    ASSERT(ErrorCodes::OK == std::error_code());
    ASSERT(std::error_code() == ErrorCodes::OK);
}

}  // namespace
}  // namespace mongo
