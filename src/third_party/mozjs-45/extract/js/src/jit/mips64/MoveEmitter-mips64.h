/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 * vim: set ts=8 sts=4 et sw=4 tw=99:
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef jit_mips64_MoveEmitter_mips64_h
#define jit_mips64_MoveEmitter_mips64_h

#include "jit/mips-shared/MoveEmitter-mips-shared.h"

namespace js {
namespace jit {

class MoveEmitterMIPS64 : public MoveEmitterMIPSShared
{
    void emitDoubleMove(const MoveOperand& from, const MoveOperand& to);
    void breakCycle(const MoveOperand& from, const MoveOperand& to,
                    MoveOp::Type type, uint32_t slot);
    void completeCycle(const MoveOperand& from, const MoveOperand& to,
                       MoveOp::Type type, uint32_t slot);

  public:
    MoveEmitterMIPS64(MacroAssembler& masm)
      : MoveEmitterMIPSShared(masm)
    { }
};

typedef MoveEmitterMIPS64 MoveEmitter;

} // namespace jit
} // namespace js

#endif /* jit_mips64_MoveEmitter_mips64_h */
