/* ###
 * IP: GHIDRA
 * NOTE: iOS? kext? all that OK?
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
package ghidra.app.util.bin.format.macho.commands.dyld;

import java.util.List;

import ghidra.app.util.bin.format.macho.*;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.*;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractClassicProcessor {
	protected MachHeader header;
	protected Program program;

	protected AbstractClassicProcessor(MachHeader header, Program program) {
		super();
		this.header = header;
		this.program = program;
	}

	final public void perform(String segmentName, String sectionName, long addressValue,
			String fromDylib, NList nList, boolean isWeak, TaskMonitor monitor) throws Exception {

//		if ( SystemUtilities.isInDevelopmentMode() ) {
//			System.out.println( "CLASSIC: " +segmentName + " " + sectionName + " " +
//					Long.toHexString( addressValue ) + " " + fromDylib + " " +
//					nList.getString() + " " + isWeak );
//		}

		monitor.setMessage("Performing bind: " + nList.getString());

		Language language = program.getLanguage();
		Memory memory = program.getMemory();
		Listing listing = program.getListing();
		AddressFactory addressFactory = program.getAddressFactory();
		AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();

		Address address = defaultAddressSpace.getAddress(addressValue);

		DataConverter converter = DataConverter.getInstance(language.isBigEndian());

		Symbol symbol = getSymbol(nList);

		if (symbol == null) {
			return;
		}

		listing.setComment(symbol.getAddress(), CodeUnit.PLATE_COMMENT, fromDylib);

		long offset = symbol.getAddress().getOffset();

		boolean handled = false;

		int fileType = header.getFileType();

		byte originalBytes[] = new byte[0];

		switch (fileType) {

			case MachHeaderFileTypes.MH_EXECUTE:
			case MachHeaderFileTypes.MH_DYLIB:
			case MachHeaderFileTypes.MH_BUNDLE:
			case MachHeaderFileTypes.MH_DYLINKER: {

				byte[] bytes = (program.getDefaultPointerSize() == 8) ? converter.getBytes(offset)
						: converter.getBytes((int) offset);

				originalBytes = new byte[bytes.length];
				memory.getBytes(address, originalBytes);
				memory.setBytes(address, bytes);

				handled = true;

				break;
			}
			case MachHeaderFileTypes.MH_KEXT_BUNDLE: {

				if (header.getCpuType() == CpuTypes.CPU_TYPE_X86 ||
					header.getCpuType() == CpuTypes.CPU_TYPE_X86_64) {

					MemoryBlock block = memory.getBlock(address);

					if (block.isExecute()) { //then we must be fixing up code...
						byte instructionByte = memory.getByte(address.subtract(1));
						if (instructionByte == (byte) 0xe8 || //relative 32-bit call
							instructionByte == (byte) 0xe9) { //relative 32-bit jump

							long difference = offset - addressValue - 4;
							byte[] bytes = converter.getBytes((int) difference);
							originalBytes = new byte[bytes.length];
							memory.getBytes(address, originalBytes);
							memory.setBytes(address, bytes);
							handled = true;
						}
					}
					else {
						byte[] bytes = (program.getDefaultPointerSize() == 8)
								? converter.getBytes(offset) : converter.getBytes((int) offset);

						originalBytes = new byte[bytes.length];
						memory.getBytes(address, originalBytes);
						memory.setBytes(address, bytes);
						handled = true;
					}
				}
				else if (header.getCpuType() == CpuTypes.CPU_TYPE_POWERPC) {//TODO powerpc kext files
					if (SystemUtilities.isInDevelopmentMode()) {
						System.out.println("CPU_TYPE_POWERPC");
					}
				}
				else if (header.getCpuType() == CpuTypes.CPU_TYPE_ARM) {//TODO ios arm kext files
					if (SystemUtilities.isInDevelopmentMode()) {
						System.out.println("CPU_TYPE_ARM ");
					}
				}

				break;
			}
			case MachHeaderFileTypes.MH_OBJECT: {
				byte[] bytes = (program.getDefaultPointerSize() == 8) ? converter.getBytes(offset)
						: converter.getBytes((int) offset);

				originalBytes = new byte[bytes.length];
				memory.getBytes(address, originalBytes);
				memory.setBytes(address, bytes);
				handled = true;
				break;
			}
			default: {
				break;
			}
		}

		// put an entry in the relocation table, handled or not
		String symbolName = symbol.getName();
		program.getRelocationTable().add(address, fileType, new long[0], originalBytes, symbolName);

		if (!handled) {
			program.getBookmarkManager().setBookmark(address, BookmarkType.ERROR,
				"Unhandled Classic Binding", "Unable to fixup classic binding. " +
					"This instruction will contain an invalid destination / fixup.");
		}
	}

	/**
	 * Return the Symbol for the specified NList.
	 * Looks in the global namespace first.
	 */
	protected Symbol getSymbol(NList nList) {
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator symbolIterator = symbolTable.getSymbols(nList.getString());
		if (symbolIterator.hasNext()) {
			return symbolIterator.next();
		}
		return null;
	}

	protected Section getSectionName(long address) {
		List<Section> sections = header.getAllSections();
		for (Section section : sections) {
			if (section.getAddress() <= address &&
				address < section.getAddress() + section.getSize()) {
				return section;
			}
		}
		return null;
		//throw new RuntimeException( "Classic bind: No section for specified address: " + Long.toHexString( address ) );
	}

	protected String getClassicOrdinalName(int libraryOrdinal) {
		switch (libraryOrdinal) {
			case NListConstants.SELF_LIBRARY_ORDINAL: {
				return "this-image";
			}
			case NListConstants.EXECUTABLE_ORDINAL: {
				return "main-executable";
			}
			case NListConstants.DYNAMIC_LOOKUP_ORDINAL: {
				return "flat-namespace";
			}
		}
		List<DynamicLibraryCommand> dylibCommands =
			header.getLoadCommands(DynamicLibraryCommand.class);
		if (libraryOrdinal >= dylibCommands.size()) {
			return "dyld info library ordinal out of range" + Integer.toHexString(libraryOrdinal);
		}
		DynamicLibraryCommand dylibCommand = dylibCommands.get(libraryOrdinal);
		DynamicLibrary dynamicLibrary = dylibCommand.getDynamicLibrary();
		LoadCommandString name = dynamicLibrary.getName();
		return name.getString();
	}

	/**
	 * Returns the relocation base.
	 * If the program is 64-bit (x86 or PowerPC), then
	 * return the VM address of the first segment with W bit.
	 * Otherwise, just return first segment VM address.
	 */
	protected long getRelocationBase() {
		List<SegmentCommand> segments = header.getLoadCommands(SegmentCommand.class);
		if (program.getDefaultPointerSize() == 8) {
			if ((header.getFlags() & MachHeaderFlags.MH_SPLIT_SEGS) != 0) {
				for (SegmentCommand segment : segments) {
					if (segment.isWrite()) {
						return segment.getVMaddress();
					}
				}
			}
		}
		SegmentCommand firstSegment = segments.get(0);
		return firstSegment.getVMaddress();
	}
}
