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
package ghidra.pcode.emu.jit.decode;

import java.util.List;

import ghidra.pcode.emu.jit.JitPassage.AddrCtx;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A list of contiguous instructions connected by fall through, along with their emitted p-code ops
 * 
 * @param start the address and contextreg value that seeded this stride
 * @param instructions the instructions in the order decoded
 * @param ops the ops in the order decoded and emitted
 * @see JitPassageDecoder
 */
record DecodedStride(AddrCtx start, List<Instruction> instructions, List<PcodeOp> ops) {}
