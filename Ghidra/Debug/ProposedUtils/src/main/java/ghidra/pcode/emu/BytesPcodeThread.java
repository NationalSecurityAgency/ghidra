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
package ghidra.pcode.emu;

import ghidra.program.model.address.AddressSpace;

public class BytesPcodeThread extends AbstractModifiedPcodeThread<byte[]> {
	public BytesPcodeThread(String name, AbstractPcodeMachine<byte[]> machine) {
		super(name, machine);
	}

	@Override
	protected int getBytesChunk(byte[] res, AddressSpace spc, long off, int size,
			boolean stopOnUnintialized) {
		byte[] var = state.getVar(spc, off, size, true);
		System.arraycopy(var, 0, res, 0, var.length);
		return var.length;
	}

	@Override
	protected void setBytesChunk(byte[] val, AddressSpace spc, long off, int size) {
		state.setVar(spc, off, size, true, val);
	}
}
