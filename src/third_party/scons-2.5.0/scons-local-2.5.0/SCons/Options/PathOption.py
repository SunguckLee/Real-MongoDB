#
# Copyright (c) 2001 - 2016 The SCons Foundation
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
# KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

__revision__ = "src/engine/SCons/Options/PathOption.py rel_2.5.0:3543:937e55cd78f7 2016/04/09 11:29:54 bdbaddog"

__doc__ = """Place-holder for the old SCons.Options module hierarchy

This is for backwards compatibility.  The new equivalent is the Variables/
class hierarchy.  These will have deprecation warnings added (some day),
and will then be removed entirely (some day).
"""

import SCons.Variables
import SCons.Warnings

warned = False

class _PathOptionClass(object):
    def warn(self):
        global warned
        if not warned:
            msg = "The PathOption() function is deprecated; use the PathVariable() function instead."
            SCons.Warnings.warn(SCons.Warnings.DeprecatedOptionsWarning, msg)
            warned = True

    def __call__(self, *args, **kw):
        self.warn()
        return SCons.Variables.PathVariable(*args, **kw)

    def PathAccept(self, *args, **kw):
        self.warn()
        return SCons.Variables.PathVariable.PathAccept(*args, **kw)

    def PathIsDir(self, *args, **kw):
        self.warn()
        return SCons.Variables.PathVariable.PathIsDir(*args, **kw)

    def PathIsDirCreate(self, *args, **kw):
        self.warn()
        return SCons.Variables.PathVariable.PathIsDirCreate(*args, **kw)

    def PathIsFile(self, *args, **kw):
        self.warn()
        return SCons.Variables.PathVariable.PathIsFile(*args, **kw)

    def PathExists(self, *args, **kw):
        self.warn()
        return SCons.Variables.PathVariable.PathExists(*args, **kw)

PathOption = _PathOptionClass()

# Local Variables:
# tab-width:4
# indent-tabs-mode:nil
# End:
# vim: set expandtab tabstop=4 shiftwidth=4:
