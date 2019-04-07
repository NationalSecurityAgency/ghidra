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
// This script tries to condense all undefined, unlabeled repeating bytes (ie all 0's or ff's) at
// the end of the current memory block. If all conditions are met it will create an array of bytes
// Note: this will not work in uninitialized memory
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AlignmentDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;


/**
 * 
 *
 * Script to condense all undefined repeating bytes (ie all 0's or ff's) at the end of the current
 * memory block
 */
public class CondenseRepeatingBytesAtEndOfMemory extends GhidraScript {
	
	@Override
    public void run() throws Exception {		
			
		if (currentAddress == null) {
			println("No Location.");
		    return;
		}
		MemoryBlock memoryBlock = currentProgram.getMemory().getBlock(currentAddress);
		if(!memoryBlock.isInitialized()){
			println("Script cannot run in uninitialized memory.");
			return;
		}
		Listing listing = currentProgram.getListing();
		

		Address currentAddr = currentAddress;        
		
		boolean isInitializedBlock = memoryBlock.isInitialized();
		if(isInitializedBlock){
			currentAddr = memoryBlock.getEnd();
			println("end of byte addr is " + currentAddr);
			byte repeatingByte = currentProgram.getMemory().getByte(currentAddr);
			
		
			MemoryBlock currentMemoryBlock = null;		
		
			
			// search for next repeatedByte from the end of memory
			// until it hits defined area or different byte		
						
			byte prevByte = repeatingByte;
			int repeatLen = 0;
			boolean noCollisions = listing.isUndefined(currentAddr,currentAddr);
			boolean hasLabels = currentProgram.getSymbolTable().hasSymbol(currentAddr);
			println("no collisions at end = " + noCollisions);
			currentMemoryBlock = currentProgram.getMemory().getBlock(currentAddr);
			while((prevByte == repeatingByte) && (noCollisions) && (currentMemoryBlock.equals(memoryBlock)) && (!hasLabels)){
				repeatLen++;
				currentAddr = currentAddr.addNoWrap(-1);
				prevByte = currentProgram.getMemory().getByte(currentAddr);
				noCollisions = listing.isUndefined(currentAddr,currentAddr);
				hasLabels = currentProgram.getSymbolTable().hasSymbol(currentAddr);
				currentMemoryBlock = currentProgram.getMemory().getBlock(currentAddr);					
			}
			if(repeatLen > 0){
			// this takes care of the last one tested that failed
			currentAddr = currentAddr.addNoWrap(1);												
			listing.createData(currentAddr, new AlignmentDataType(), repeatLen);				
			
			println("Applied Alignment datatype at " + currentAddr.toString());												
			 
			}
			else{
				println("No repeating bytes OR data already defined at end of " + memoryBlock);
			}
		}
		else{
			println("Cannot condense uninitialized memory.");
		}		
	}	
}

