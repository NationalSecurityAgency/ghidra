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
import ghidra.app.script.GhidraScript;
import ghidra.app.util.disassemble.GNUExternalDisassembler;
import ghidra.app.util.disassemble.GnuDisassembledInstruction;
import ghidra.program.model.address.Address;

import java.util.List;

public class GNUDisassembleBlockScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		if (currentProgram == null || currentAddress == null) {
			return;
		}

		GNUExternalDisassembler dis = new GNUExternalDisassembler();

		Address addr = currentAddress.getNewAddress(currentAddress.getOffset() & -32); // block aligned address

		List<GnuDisassembledInstruction> results = dis.getBlockDisassembly(currentProgram, addr, 5);

		if (results == null) {
			println("Block Disassembly Failed!");
			return;
		}

		int maxByteLen = 0;
		for (GnuDisassembledInstruction result : results) {
			maxByteLen = Math.max(maxByteLen, result.getNumberOfBytesInInstruction());
		}

		StringBuilder sb = new StringBuilder();
		for (GnuDisassembledInstruction result : results) {
			sb.append(addr.toString());
			sb.append(' ');
			int cnt = 0;
			byte[] bytes = new byte[result.getNumberOfBytesInInstruction()];
			currentProgram.getMemory().getBytes(addr, bytes);
			for (byte b : bytes) {
				if (b >= 0 && b < 0x10) {
					sb.append('0');
				}
				sb.append(Integer.toHexString(b & 0xff));
				sb.append(' ');
				++cnt;
			}
			if (cnt < maxByteLen) {
				int pad = (maxByteLen - cnt) * 3;
				for (int i = 0; i < pad; i++) {
					sb.append(' ');
				}
			}
			sb.append(result.getInstruction());
			sb.append("\n");
			addr = addr.add(bytes.length);
		}
		if (sb.length() != 0) {
			println("Block Disassembly:\n" + sb.toString());
		}

	}

}
