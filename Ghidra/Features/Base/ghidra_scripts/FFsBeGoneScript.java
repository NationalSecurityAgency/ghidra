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
//Rid us of those pesky FF's that become bad instructions
//@category Cleanup

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;

import java.util.Arrays;

public class FFsBeGoneScript extends GhidraScript {
	private Address addr;
	byte[] bytes = new byte[10];
	byte[] masks = new byte[10];

	@Override
	public void run() throws Exception {
		DataType wordDataType =
			currentProgram.getDataTypeManager().getDataType(new CategoryPath("/"), "word");
		if (wordDataType == null) {
			throw new Exception("Data type 'word' could not be found in the program.");
		}
		Arrays.fill(bytes, (byte) 0xff);
		Arrays.fill(masks, (byte) 0xff);
		addr = currentProgram.getMemory().getMinAddress();
		advance();
		while (addr != null && !monitor.isCancelled()) {
			byte byt = 0;
			try {
				byt = currentProgram.getMemory().getByte(addr);
			}
			catch (Exception e) {
				advance();
				continue;
			}
			while ((byt & 0xff) == 0xff) {
				if (isUndefinedData(addr)) {
					try {
						createData(addr, wordDataType);
					}
					catch (Exception e) {
						println("Could not create data at " + addr.toString());
						addr = addr.next();
						break;
					}
				}
				else {
					break;
				}
				addr = currentProgram.getListing().getDefinedDataAt(addr).getMaxAddress().next();
				try {
					byt = currentProgram.getMemory().getByte(addr);
				}
				catch (Exception e) {
					break;
				}
			}
			advance();
		}
	}

	private void advance() {
		if (addr == null) {
			return;
		}
		addr = currentProgram.getMemory().findBytes(addr, bytes, masks, true, monitor);
		if (addr != null) {
			if (!isUndefinedData(addr)) {
				if (currentProgram.getListing().getInstructionContaining(addr) != null) {
					addr =
						currentProgram.getListing().getInstructionContaining(addr).getMaxAddress().next();
				}
				else if (currentProgram.getListing().getDefinedDataContaining(addr) != null) {
					addr =
						currentProgram.getListing().getDefinedDataContaining(addr).getMaxAddress().next();
				}
				advance();
			}
		}
	}

	private boolean isUndefinedData(Address address) {
		if (currentProgram.getListing().getInstructionContaining(address) != null) {
			return false;
		}
		if (currentProgram.getListing().getDefinedDataContaining(address) != null) {
			return false;
		}
		return true;
	}

}
