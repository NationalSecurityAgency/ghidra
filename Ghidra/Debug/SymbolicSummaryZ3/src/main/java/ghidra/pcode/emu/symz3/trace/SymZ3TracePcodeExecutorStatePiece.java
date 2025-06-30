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
package ghidra.pcode.emu.symz3.trace;

import java.util.Map;

import ghidra.pcode.exec.trace.TracePcodeExecutorStatePiece;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.program.model.lang.Register;
import ghidra.symz3.model.SymValueZ3;

/**
 * The trace-integrated state piece for holding symbolic values
 */
public class SymZ3TracePcodeExecutorStatePiece
		extends AbstractSymZ3TracePcodeExecutorStatePiece {

	public SymZ3TracePcodeExecutorStatePiece(PcodeTraceDataAccess data) {
		super(data);
	}

	@Override
	public TracePcodeExecutorStatePiece<SymValueZ3, SymValueZ3> fork() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Map<Register, SymValueZ3> getRegisterValues() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		throw new UnsupportedOperationException();
	}
}
