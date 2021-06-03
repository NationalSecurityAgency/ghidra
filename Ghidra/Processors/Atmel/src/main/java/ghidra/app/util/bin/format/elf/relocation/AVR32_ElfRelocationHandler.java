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
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.NotFoundException;

public class AVR32_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_AVR32;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation,
			Address relocationAddress) throws MemoryAccessException, NotFoundException {

		Program program = elfRelocationContext.getProgram();

		Memory memory = program.getMemory();
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

		int type = relocation.getType();
		int symbolIndex = relocation.getSymbolIndex();

		long addend = relocation.getAddend(); // will be 0 for REL case

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if ((symbolIndex == 0) && (elf.e_machine() == ElfConstants.EM_AVR32)) {
			//System.out.println("ZERO_SYMBOL_TYPE = " + type + ", Offset = " + offset + ", Addend = " + addend);
		}
		else if (symbolIndex == 0) {//TODO
			return;
		}

		long offset = (int) relocationAddress.getOffset();

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		long symbolValue = elfRelocationContext.getSymbolValue(sym);

		int oldValue = memory.getInt(relocationAddress);

		if (elf.e_machine() == ElfConstants.EM_AVR32) {
			int newValueShiftToAligntoUpper = 0;
			switch (type) {
				case AVR32_ElfRelocationConstants.R_AVR32_NONE:
					break;
				case AVR32_ElfRelocationConstants.R_AVR32_32:
					int newValue = (((int) symbolValue + (int) addend) & 0xffffffff);
					memory.setInt(relocationAddress, newValue);
					break;

				case AVR32_ElfRelocationConstants.R_AVR32_DIFF32:
					newValue = (((int) symbolValue + (int) addend + oldValue) & 0xffffffff);
					memory.setInt(relocationAddress, newValue);
					break;
				case AVR32_ElfRelocationConstants.R_AVR32_22H_PCREL://(BR{cond4})
					newValue = (int) ((symbolValue + (int) addend - offset) >> 1);
					int nVpart1 = (newValue & 0x0000ffff);
					int nVpart2 = (newValue & 0x00010000);
					int nVpart3 = (newValue & 0x001e0000);
					int newValueParts =
						(((nVpart3 << 8) | (nVpart2 << 4) | (nVpart1)) & 0x1e10ffff);
					int newValueSet = (oldValue | newValueParts);
					memory.setInt(relocationAddress, newValueSet);
					break;
				case AVR32_ElfRelocationConstants.R_AVR32_11H_PCREL: //WORKING! (RJMP)
					newValue = (int) (((symbolValue + (int) addend - offset) >> 1) << 4);
					int tempNewValHold = (newValue & 0x00000ff3);
					int tempDispHold = ((newValue & 0x00003000) >> 12);
					newValueShiftToAligntoUpper = ((tempNewValHold << 16) | (tempDispHold << 16));
					newValue = ((oldValue | newValueShiftToAligntoUpper) & 0xffffffff);
					memory.setInt(relocationAddress, newValue);
					break;
				case AVR32_ElfRelocationConstants.R_AVR32_9H_PCREL://WORKING! (BR{cond3})
					newValue =
						(int) ((((symbolValue + (int) addend - offset) >> 1) << 4) & 0x00000ff0);
					newValueShiftToAligntoUpper = (newValue << 16);
					newValue = ((oldValue | newValueShiftToAligntoUpper) & 0xffffffff);
					memory.setInt(relocationAddress, newValue);
					break;
				case AVR32_ElfRelocationConstants.R_AVR32_32_CPENT: //WORKING! (POINTER_SYMBOL_PLACEMENT)
					newValue = (((int) symbolValue + (int) addend) & 0xffffffff);
					memory.setInt(relocationAddress, newValue);

					Address currNewAddress = space.getAddress(newValue);

					if (!memory.contains(currNewAddress)) {
						int currElfSymbolInfoBind = sym.getBind();
						int currElfSymbolInfoType = sym.getType();

						if ((currElfSymbolInfoBind == ElfSymbol.STB_GLOBAL) &&
							((currElfSymbolInfoType == ElfSymbol.STT_OBJECT) ||
								(currElfSymbolInfoType == ElfSymbol.STT_NOTYPE))) {
							String currElfSymbolName = sym.getNameAsString();

							long currElfSymbolSize = sym.getSize();
							if (currElfSymbolSize == 0) {
								currElfSymbolSize = 2;
							}

							StringBuffer newSectionNameBuff = new StringBuffer();
							newSectionNameBuff.append("cpool.");
							newSectionNameBuff.append(currElfSymbolName);

							StringBuffer newSectionTypeBuff = new StringBuffer();
							newSectionTypeBuff.append("Constant Pool ");
							boolean isReadable = true;
							boolean isWritable = true;
							boolean isExecutable = true;

							if (currElfSymbolInfoType == ElfSymbol.STT_OBJECT) {
								isReadable = true;
								isWritable = true;
								isExecutable = false;
								newSectionTypeBuff.append("Global Variable Object");
							}
							else {
								isReadable = true;
								isWritable = false;
								isExecutable = true;
								newSectionTypeBuff.append("Global External Function");
							}
							ElfLoadHelper loadHelper = elfRelocationContext.getLoadHelper();
							MemoryBlockUtils.createInitializedBlock(program, false,
								newSectionNameBuff.toString(), currNewAddress, currElfSymbolSize,
								newSectionTypeBuff.toString(), "AVR32-ELF Loader", isReadable,
								isWritable, isExecutable, loadHelper.getLog());
						}
					}
					try {
						Listing listing = program.getListing();
						listing.createData(relocationAddress, StructConverter.POINTER,
							relocationAddress.getPointerSize());
					}
					catch (CodeUnitInsertionException cuie) {
						System.out.println("Attempting to create Pointer Data: " + cuie);
					}
					break;
				case AVR32_ElfRelocationConstants.R_AVR32_CPCALL: //WORKING! (MCALL)
					int checkForPC = (oldValue & 0x000f0000);
					if (checkForPC == 0xf0000) {
						newValue =
							(int) (((symbolValue + (int) addend - (offset & 0xfffffffc)) >> 2) &
								0x0000ffff);
					}
					else {
						newValue =
							(int) (((symbolValue + (int) addend - offset) >> 2) & 0x0000ffff);
					}
					int newValueSet_CPCALL = ((oldValue | newValue) & 0xffffffff);
					memory.setInt(relocationAddress, newValueSet_CPCALL);
					break;
				case AVR32_ElfRelocationConstants.R_AVR32_9W_CP: //WORKING! (LDDPC)
					newValue =
						(int) ((((symbolValue + (int) addend - (offset & 0xfffffffc)) >>> 2) << 4) &
							0x000007f0);
					newValueShiftToAligntoUpper = (newValue << 16);
					newValue = ((oldValue | newValueShiftToAligntoUpper) & 0xffffffff);
					memory.setInt(relocationAddress, newValue);
					break;
				case AVR32_ElfRelocationConstants.R_AVR32_ALIGN:
					//System.out.print("-> type = " + type + ", symbolValue = " + symbolValue + ", addend = " + addend + ", offset = " + offset + " - ");
					/*if((addend == 2) && (oldValueLong == 0)){
					    try{
					        Listing listing = prog.getListing();
					        listing.createData(relocationAddress, StructConverter.WORD, (int)addend);
					    }catch(CodeUnitInsertionException cuie){
					        System.out.println("Attempting to create Pointer Data: " + cuie);
					    }
					    System.out.println("  HANDLED AVR relocation: R_AVR32_ALIGN at "+relocationAddress + ", New = " + newValue);
					}*/
					//System.out.println("  HANDLED AVR relocation: R_AVR32_ALIGN at "+relocationAddress + ", OldValue = " + Integer.toHexString(oldValue));
					break;

				//TODO: THE FOLLOWING:
				/*case AVR32_ElfRelocationConstants.R_AVR32_16_CP:
				    //System.out.print("-> type = " + type + ", symbolValue = " + symbolValue + ", addend = " + addend + ", offset = " + offset + " - ");
				    //newValue = (int)((symbolValue + (int)addend - offset)) & 0x0000ffff;
				    //memory.setInt(relocationAddress, newValue);
				    //System.out.println("? HANDLED AVR relocation: R_AVR32_16_CP at "+relocationAddress + ", New = " + Integer.toHexString(newValue));
				    break;*/
				/*case AVR32_ElfRelocationConstants.R_AVR32_RELATIVE:
				    newValue = (((int)elf.getImageBase() + (int)addend) & 0xffffffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_RELATIVE at "+relocationAddress + ", New = " + newValue);
				    break;  
				    */
				/*case AVR32_ElfRelocationConstants.R_AVR32_16:
				    newValue = ((symbolValue + (int)addend) & 0x0000ffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_16 at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_8:
				    newValue = ((symbolValue + (int)addend) & 0x000000ff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_8 at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_32_PCREL:
				    newValue = (int)((symbolValue + (int)addend - offset) & 0xffffffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_32_PCREL at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_16_PCREL:
				    newValue = (int)((symbolValue + (int)addend - offset) & 0x0000ffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_16_PCREL at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_8_PCREL:
				    newValue = (int)((symbolValue + (int)addend - offset) & 0x000000ff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_8_PCREL at "+relocationAddress + ", New = " + newValue);
				    break;*/
				/*case AVR32_ElfRelocationConstants.R_AVR32_DIFF16:
				    newValue = ((symbolValue) & 0x0000ffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_DIFF8 at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_DIFF8:
				    newValue = ((symbolValue) & 0x000000ff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_DIFF8 at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_21S:
				    newValue = ((symbolValue + (int)addend) & 0x1e10ffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_21S at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_16U: //Use long to accommodate the Unsignedness...
				    long newValueLong = ((symbolValue + addend) & 0x0000ffff);
				    memory.setLong(relocationAddress, newValueLong);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_16U at "+relocationAddress + ", NewLong = " + newValueLong);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_16S:
				    newValue = ((symbolValue + (int)addend) & 0x0000ffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_16S at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_8S:
				    newValue = (((symbolValue + (int)addend) << 4) & 0x00000ff0);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_8S at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_8S_EXT:
				    newValue = ((symbolValue + (int)addend) & 0x000000ff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_8S_EXT at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_18W_PCREL:
				    newValue = (int)(((symbolValue + (int)addend - offset) >> 2) & 0x0000ffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_18W_PCREL at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_16B_PCREL:
				    newValue = (int)((symbolValue + (int)addend - offset) & 0xffffffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_16B_PCREL at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_16N_PCREL:
				    newValue = (int)((offset - symbolValue - (int)addend) & 0x0000ffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_16N_PCREL at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_14UW_PCREL:
				    newValue = (int)(((symbolValue + (int)addend - offset) >>> 2) & 0x0000f0ff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_14UW_PCREL at "+relocationAddress + ", New = " + newValue);
				    break;*/
				/*case AVR32_ElfRelocationConstants.R_AVR32_10UW_PCREL:
				    newValue = (int)(((symbolValue + (int)addend - offset) >>> 2) & 0x000000ff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_10UW_PCREL at "+relocationAddress + ", New = " + newValue);
				    break;*/
				/*case AVR32_ElfRelocationConstants.R_AVR32_9UW_PCREL:
				    newValue = (int)((((symbolValue + (int)addend - offset) >>> 2) << 4) & 0x000007f0);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_9UW_PCREL at "+relocationAddress + ", New = " + newValue);
				    break;
				    
				case AVR32_ElfRelocationConstants.R_AVR32_HI16:
				    newValue = (((symbolValue + (int)addend) >> 16) & 0x0000ffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_HI16 at "+relocationAddress + ", New = " + newValue);
				    break;
				case AVR32_ElfRelocationConstants.R_AVR32_LO16:
				    newValue = ((symbolValue + (int)addend) & 0x0000ffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_LO16 at "+relocationAddress + ", New = " + newValue);
				    break;
				    
				case AVR32_ElfRelocationConstants.R_AVR32_GOTPC:
				    ElfSectionHeader dotgot = elf.getGOT();
				    MemoryBlock got = memory.getBlock(dotgot.getNameAsString());
				    newValue = ((symbolValue + (int)addend - (int)got.getStart().getOffset()) & 0xffffffff);
				    memory.setInt(relocationAddress, newValue);
				    System.out.println("  HANDLED AVR relocation: R_AVR32_GOTPC at "+relocationAddress + ", New = " + newValue);
				    break;*/
				default:
					String symbolName = sym.getNameAsString();
					markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
						elfRelocationContext.getLog());
					break;
			}
		}
	}

}
