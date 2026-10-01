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

import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.program.model.listing.Instruction;

/**
 * An interface on {@link PcodeExecutor} when that executor can decode and interpret an
 * {@link Instruction}
 */
public interface CanDecode {
	/**
	 * {@return the current instruction, decoding it if needed}
	 */
	PseudoInstruction decodeInstruction();
}
