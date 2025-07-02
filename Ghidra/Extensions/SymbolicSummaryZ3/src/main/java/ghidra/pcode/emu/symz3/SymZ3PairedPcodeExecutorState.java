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
package ghidra.pcode.emu.symz3;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.symz3.plain.SymZ3Space;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.symz3.model.SymValueZ3;

public interface SymZ3PairedPcodeExecutorState
		extends PcodeExecutorState<Pair<byte[], SymValueZ3>> {

	PcodeExecutorStatePiece<byte[], byte[]> getLeft();

	AbstractSymZ3PcodeExecutorStatePiece<? extends SymZ3Space> getRight();
}
