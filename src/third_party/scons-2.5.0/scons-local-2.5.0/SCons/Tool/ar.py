"""SCons.Tool.ar

Tool-specific initialization for ar (library archive).

There normally shouldn't be any need to import this module directly.
It will usually be imported through the generic SCons.Tool.Tool()
selection method.

"""

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

__revision__ = "src/engine/SCons/Tool/ar.py rel_2.5.0:3543:937e55cd78f7 2016/04/09 11:29:54 bdbaddog"

import SCons.Defaults
import SCons.Tool
import SCons.Util


def generate(env):
    """Add Builders and construction variables for ar to an Environment."""
    SCons.Tool.createStaticLibBuilder(env)

    env['AR']          = 'ar'
    env['ARFLAGS']     = SCons.Util.CLVar('rc')
    env['ARCOM']       = '$AR $ARFLAGS $TARGET $SOURCES'
    env['LIBPREFIX']   = 'lib'
    env['LIBSUFFIX']   = '.a'

    if env.Detect('ranlib'):
        env['RANLIB']      = 'ranlib'
        env['RANLIBFLAGS'] = SCons.Util.CLVar('')
        env['RANLIBCOM']   = '$RANLIB $RANLIBFLAGS $TARGET'

def exists(env):
    return env.Detect('ar')

# Local Variables:
# tab-width:4
# indent-tabs-mode:nil
# End:
# vim: set expandtab tabstop=4 shiftwidth=4:
