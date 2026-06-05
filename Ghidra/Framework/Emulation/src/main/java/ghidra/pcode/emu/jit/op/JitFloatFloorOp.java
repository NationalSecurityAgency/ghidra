/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.pcode.emu.jit.op;

import ghidra.pcode.emu.jit.var.JitOutVar;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The use-def node for a {@link PcodeOp#FLOAT_FLOOR}.
 * 
 * @param op the p-code op
 * @param out the use-def variable node for the output
 * @param u the use-def node for the input operand
 */
public record JitFloatFloorOp(PcodeOp op, JitOutVar out, JitVal u) implements JitFloatUnOp {}
