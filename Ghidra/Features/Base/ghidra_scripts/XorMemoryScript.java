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
//XOR's the memory of the current program.
//@category Memory

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class XorMemoryScript extends GhidraScript {

    @Override
    public void run() throws Exception {
    	
    	// default to the current memory block
    	Memory memory = currentProgram.getMemory();
    	MemoryBlock block = memory.getBlock(currentAddress);
    	AddressSetView set = new AddressSet(block.getStart(),block.getEnd());
    	
    	if (currentSelection != null && !currentSelection.isEmpty()) {
    		set = currentSelection;
    	}
    	
    	byte[] xorValues = askBytes("XorValue", "Values to xor with selected memory:");
    	
    	int valueLength = xorValues.length;
    	int xorIndex = 0;
    	
    	AddressIterator aIter = set.getAddresses(true);
    	
    	while (aIter.hasNext() && !monitor.isCancelled()) {
    		Address addr = aIter.next();
    		monitor.setMessage(addr.toString());
    		byte xorValue = xorValues[xorIndex];
    		byte b = memory.getByte(addr);
    		b = (byte) (b ^ xorValue);
    		memory.setByte(addr, b);
    		xorIndex += 1;
    		xorIndex = xorIndex % valueLength;
    	}
    }

}
