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
package ghidra.app.emulator.memory;

import ghidra.program.model.address.Address;

public class ProgramMappedLoadImage implements MemoryLoadImage {

	private ProgramMappedMemory pmm;
	//private Language lang;
	
	public ProgramMappedLoadImage(ProgramMappedMemory memory) {
		this.pmm = memory;
		//this.lang = memory.getProgram().getLanguage();
	}
	
	@Override
	public byte[] loadFill(byte[] bytes, int size, Address addr, int offset, boolean generateInitializedMask) {
		return pmm.read(bytes, size, addr, offset, generateInitializedMask);
//		boolean initialized = false;
//		for (byte b : bytes) {
//			if (b != 0) {
//				initialized = true;
//				break;
//			}
//		}
//		return generateInitializedMask ? MemoryPage.getInitializedMask(size, initialized) : null;  
	}

	@Override
	public void writeBack(byte[] bytes, int size, Address addr, int offset) {
		pmm.write(bytes, size, addr, offset);
	}

	@Override
	public void dispose() {
		pmm.dispose();
	}
	
}
