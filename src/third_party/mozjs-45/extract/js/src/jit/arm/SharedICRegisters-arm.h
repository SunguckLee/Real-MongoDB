/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 * vim: set ts=8 sts=4 et sw=4 tw=99:
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef jit_arm_SharedICRegisters_arm_h
#define jit_arm_SharedICRegisters_arm_h

#include "jit/MacroAssembler.h"

namespace js {
namespace jit {

// r15 = program-counter
// r14 = link-register

// r13 = stack-pointer
// r11 = frame-pointer
static MOZ_CONSTEXPR_VAR Register BaselineFrameReg = r11;
static MOZ_CONSTEXPR_VAR Register BaselineStackReg = sp;

// ValueOperands R0, R1, and R2.
// R0 == JSReturnReg, and R2 uses registers not preserved across calls. R1 value
// should be preserved across calls.
static MOZ_CONSTEXPR_VAR ValueOperand R0(r3, r2);
static MOZ_CONSTEXPR_VAR ValueOperand R1(r5, r4);
static MOZ_CONSTEXPR_VAR ValueOperand R2(r1, r0);

// ICTailCallReg and ICStubReg
// These use registers that are not preserved across calls.
static MOZ_CONSTEXPR_VAR Register ICTailCallReg = r14;
static MOZ_CONSTEXPR_VAR Register ICStubReg     = r9;

static MOZ_CONSTEXPR_VAR Register ExtractTemp0        = InvalidReg;
static MOZ_CONSTEXPR_VAR Register ExtractTemp1        = InvalidReg;

// Register used internally by MacroAssemblerARM.
static MOZ_CONSTEXPR_VAR Register BaselineSecondScratchReg = r6;

// R7 - R9 are generally available for use within stubcode.

// Note that ICTailCallReg is actually just the link register. In ARM code
// emission, we do not clobber ICTailCallReg since we keep the return
// address for calls there.

// FloatReg0 must be equal to ReturnFloatReg.
static MOZ_CONSTEXPR_VAR FloatRegister FloatReg0      = d0;
static MOZ_CONSTEXPR_VAR FloatRegister FloatReg1      = d1;

} // namespace jit
} // namespace js

#endif /* jit_arm_SharedICRegisters_arm_h */
