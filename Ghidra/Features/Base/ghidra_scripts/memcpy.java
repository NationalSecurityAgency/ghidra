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

//Copy selected bytes to another address
//@category Memory


import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class memcpy extends GhidraScript {

	@Override
	protected void run() throws Exception {
		
		if (currentSelection == null || currentSelection.isEmpty())
		{
			printf("Please select source data\n");
			return;	
		}
		if (currentSelection.getNumAddressRanges() != 1)
		{
			printf("Please select only one address range");
			return;
		}
		AddressRange srcRange = currentSelection.getFirstRange();
		Address srcStart = srcRange.getMinAddress();
		long length = srcRange.getMaxAddress().subtract(srcStart) + 1;

		Address dstAddr = askAddress("memcpy", 
				String.format("Copy %d (0x%X) bytes from %s to", length, length, srcStart.toString()),
				currentLocation.getAddress().toString());

		Memory memory = currentProgram.getMemory();

		MemoryBlock dstBlock = memory.getBlock(dstAddr);
		if (!dstBlock.isInitialized())
		{
			printf("Please configure destignation memory as initialized");
			return;
		}

		for (long i = 0; i < length; i++)
		{
			byte b = memory.getByte(srcStart.add(i));
			memory.setByte(dstAddr.add(i), b);
		}
		
	}
}
