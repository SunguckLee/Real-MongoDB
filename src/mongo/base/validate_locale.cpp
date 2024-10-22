/*    Copyright 2014 MongoDB, Inc.
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

#include <stdexcept>

#include <boost/filesystem/path.hpp>
#include <codecvt>
#include <locale>

#include "mongo/base/init.h"

namespace mongo {

MONGO_INITIALIZER_GENERAL(ValidateLocale, MONGO_NO_PREREQUISITES, MONGO_DEFAULT_PREREQUISITES)
(InitializerContext*) {
    try {
        // Validate that boost can correctly load the user's locale
        boost::filesystem::path("/").has_root_directory();
    } catch (const std::runtime_error&) {
        return Status(ErrorCodes::BadValue,
                      "Invalid or no user locale set."
#ifndef _WIN32
                      " Please ensure LANG and/or LC_* environment variables are set correctly."
#endif
                      );
    }

#ifdef _WIN32
    // Make boost filesystem treat all strings as UTF-8 encoded instead of CP_ACP.
    std::locale loc(std::locale(""), new std::codecvt_utf8_utf16<wchar_t>);
    boost::filesystem::path::imbue(loc);
#endif

    return Status::OK();
}

}  // namespace mongo
