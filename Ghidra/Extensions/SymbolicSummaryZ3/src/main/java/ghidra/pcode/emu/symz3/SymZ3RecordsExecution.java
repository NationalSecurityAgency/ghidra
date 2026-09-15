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

import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.trace.model.target.path.KeyPath;

public interface SymZ3RecordsExecution {
	record RecInstruction(int index, SymZ3PcodeThread thread, Instruction instruction) {
		@Override
		public final String toString() {
			return "[%s]: %s".formatted(thread.getName(), instruction);
		}

		public String getThreadName() {
			return KeyPath.parse(thread.getName()).index();
		}

		public Address getAddress() {
			return instruction.getAddress();
		}
	}

	record RecOp(int index, SymZ3PcodeThread thread, PcodeOp op) {
		public String getThreadName() {
			return KeyPath.parse(thread.getName()).index();
		}

		public Address getAddress() {
			return op.getSeqnum().getTarget();
		}
	}

	public List<RecInstruction> getInstructions();

	public List<RecOp> getOps();
}
