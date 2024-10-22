"""SCons.Tool.lex

Tool-specific initialization for lex.

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

__revision__ = "src/engine/SCons/Tool/lex.py rel_2.5.0:3543:937e55cd78f7 2016/04/09 11:29:54 bdbaddog"

import os.path

import SCons.Action
import SCons.Tool
import SCons.Util

LexAction = SCons.Action.Action("$LEXCOM", "$LEXCOMSTR")

def lexEmitter(target, source, env):
    sourceBase, sourceExt = os.path.splitext(SCons.Util.to_String(source[0]))

    if sourceExt == ".lm":           # If using Objective-C
        target = [sourceBase + ".m"] # the extension is ".m".

    # This emitter essentially tries to add to the target all extra
    # files generated by flex.

    # Different options that are used to trigger the creation of extra files.
    fileGenOptions = ["--header-file=", "--tables-file="]

    lexflags = env.subst("$LEXFLAGS", target=target, source=source)
    for option in SCons.Util.CLVar(lexflags):
        for fileGenOption in fileGenOptions:
            l = len(fileGenOption)
            if option[:l] == fileGenOption:
                # A file generating option is present, so add the
                # file name to the target list.
                fileName = option[l:].strip()
                target.append(fileName)
    return (target, source)

def generate(env):
    """Add Builders and construction variables for lex to an Environment."""
    c_file, cxx_file = SCons.Tool.createCFileBuilders(env)

    # C
    c_file.add_action(".l", LexAction)
    c_file.add_emitter(".l", lexEmitter)

    c_file.add_action(".lex", LexAction)
    c_file.add_emitter(".lex", lexEmitter)

    # Objective-C
    cxx_file.add_action(".lm", LexAction)
    cxx_file.add_emitter(".lm", lexEmitter)

    # C++
    cxx_file.add_action(".ll", LexAction)
    cxx_file.add_emitter(".ll", lexEmitter)

    env["LEX"]      = env.Detect("flex") or "lex"
    env["LEXFLAGS"] = SCons.Util.CLVar("")
    env["LEXCOM"] = "$LEX $LEXFLAGS -t $SOURCES > $TARGET"

def exists(env):
    return env.Detect(["flex", "lex"])

# Local Variables:
# tab-width:4
# indent-tabs-mode:nil
# End:
# vim: set expandtab tabstop=4 shiftwidth=4:
