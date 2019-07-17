/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
// This script condenses a sequence of equal bytes into a byte array. Starts at the current address and 
// looks for bytes equal to the byte at that address in sequence until it encounters a different byte 
// value
// does not condense into new memory blocks
// does not overwrite previously defined code or memory
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AlignmentDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;

/**
 * condenses sequence of equal bytes, starting at current byte, into an array of bytes
 */
public class CondenseRepeatingBytes extends GhidraScript {
	
	@Override
    public void run() throws Exception {
		
		if (currentAddress == null) {
	            println("No Location.");
	            return;
	        }
		MemoryBlock currentMemoryBlock = currentProgram.getMemory().getBlock(currentAddress);
		if(!currentMemoryBlock.isInitialized()){
			println("Script cannot run in uninitialized memory.");
			return;
		}
			
		Listing listing = currentProgram.getListing();
		Address currentAddr = currentAddress;
		byte repeatingByte = currentProgram.getMemory().getByte(currentAddr);
		int repeatLen = 1;
		currentAddr = currentAddr.addNoWrap(1);
		byte nextByte;		
		boolean sameMemoryBlock;
		if(currentProgram.getMemory().getBlock(currentAddr).equals(currentMemoryBlock)) {
			nextByte = currentProgram.getMemory().getByte(currentAddr);
			sameMemoryBlock = true;
		}
		else{
			sameMemoryBlock = false;
			return;
		}
		
		boolean noCollisions = true;
		
		while((sameMemoryBlock) && (nextByte == repeatingByte) && (noCollisions)){
			repeatLen++;
			currentAddr = currentAddr.addNoWrap(1);
			if(currentProgram.getMemory().getBlock(currentAddr) != currentMemoryBlock){
				sameMemoryBlock = false;				
			}
			else{
				nextByte = currentProgram.getMemory().getByte(currentAddr);
				noCollisions = listing.isUndefined(currentAddr,currentAddr);
			}			
		}
		
	
		listing.createData(currentAddress, new AlignmentDataType(), repeatLen);				
		
		println("Applied Alignment datatype at " + currentAddress.toString());				
			
	}
		
}
