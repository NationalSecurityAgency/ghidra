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
// This script condenses all sequences of the current byte in current memory block only
// minimum length of 5
// does not condense into new memory blocks
// does not overwrite previously defined code or memory
// does not condense into newly referenced areas
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AlignmentDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolTable;


/**
 * Script to condense all undefined sequences matching the current byte (minimum length 5)in the current memory
 * block into byte arrays
 */
public class CondenseAllRepeatingBytes extends GhidraScript {
	
	@Override
    public void run() throws Exception {
		 if (currentAddress == null) {
	            println("No Location.");
	            return;
	        }
		Listing listing = currentProgram.getListing();
	
		Address currentAddr = currentAddress;	
	

		MemoryBlock memoryBlock = currentProgram.getMemory().getBlock(currentAddr);
		SymbolTable st = currentProgram.getSymbolTable();
		if(memoryBlock.isInitialized()){
			byte repeatingByte = currentProgram.getMemory().getByte(currentAddr);		
			String repStringNo0x = Integer.toHexString(repeatingByte & 0xff);				

			println("Condensing all runs of 5 or more " + repStringNo0x + "'s in the " + memoryBlock.getName() + " memory block.");
			
			int minRepeatLen = 5;
			byte[] repeatingBytes = new byte [minRepeatLen];
			for(int i=0;i<minRepeatLen;i++){
				repeatingBytes[i] = repeatingByte;
			}
			int repeatLen = minRepeatLen;
			// get iterator over all undefined of current memory block
			MemoryBlock currentMemoryBlock = null;
			Address start = memoryBlock.getStart();
			boolean sameMemoryBlock = true;
			
			// search for next set of minRepeatLen repeatedBytes
			// determine if in undefined area
			// if so, determine if there are more contiguous repeated bytes at that location
			// if so, make array of bytes at that location with appropriate label
			boolean isUndef;			
			while (((currentAddr = find(start,repeatingBytes)) != null) && (sameMemoryBlock == true)){
					//println(currentAddr.toString() + " " + hexRepeatingByte);	
					if(listing.isUndefined(currentAddr, currentAddr.addNoWrap(minRepeatLen-1))){
					
						int i=0;				
						while((i < minRepeatLen) && (sameMemoryBlock)){
							if(currentProgram.getMemory().getBlock(currentAddr.addNoWrap(i)).equals(memoryBlock)){
								sameMemoryBlock = true;
								i++;
							}
							else{
								sameMemoryBlock = false;
							}
						}
						isUndef = true;
					}
					else{
						isUndef = false;
						currentAddr = currentAddr.addNoWrap(1);
					}
					
					if((isUndef) && (sameMemoryBlock)){
						Address startAddr = currentAddr;
						currentAddr = currentAddr.addNoWrap(minRepeatLen);
						boolean currentAddrExists = currentProgram.getMemory().contains(currentAddr);
						if(currentAddrExists){
							byte nextByte = currentProgram.getMemory().getByte(currentAddr);
							repeatLen = minRepeatLen;
							boolean noDataCollisions = listing.isUndefined(currentAddr,currentAddr);
							boolean noLabelCollisions = st.hasSymbol(currentAddr);
							//TODO ?? add check for label collisions? 
							currentMemoryBlock = currentProgram.getMemory().getBlock(currentAddr);
							if(currentMemoryBlock.equals(memoryBlock)){
								sameMemoryBlock = true;
							}
							else{
								sameMemoryBlock = false;
							}
								
							while((currentAddrExists) && (sameMemoryBlock) && (nextByte == repeatingByte) && (noDataCollisions) && (!noLabelCollisions)){
								repeatLen++;
								currentAddr = currentAddr.addNoWrap(1);							
							
								currentAddrExists = currentProgram.getMemory().contains(currentAddr);
								if(currentAddrExists){
									currentMemoryBlock = currentProgram.getMemory().getBlock(currentAddr);
									if(currentMemoryBlock.equals(memoryBlock)){
										nextByte = currentProgram.getMemory().getByte(currentAddr);										
									}
									else{
										sameMemoryBlock = false;
									}
									noDataCollisions = listing.isUndefined(currentAddr,currentAddr);
									noLabelCollisions = st.hasSymbol(currentAddr);
																											
								}								
								
							}
						}
															
						listing.createData(startAddr, new AlignmentDataType(), repeatLen);				
						
						println("Applied Alignment datatype at " + startAddr.toString());				
						
						}
					start = currentAddr;
					}
			
		 
		}
		else{
			println("Script does not work in uninitialized memory.");
		}
	}	
}

