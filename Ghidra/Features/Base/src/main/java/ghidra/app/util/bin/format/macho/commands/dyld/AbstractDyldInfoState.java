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
package ghidra.app.util.bin.format.macho.commands.dyld;

import java.util.List;

import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.*;
import ghidra.util.task.TaskMonitor;

abstract public class AbstractDyldInfoState {
	protected MachHeader header;
	protected Program program;

	String symbolName;
	int type = 0;
	int libraryOrdinal = 0;
	long segmentOffset = 0;
	int segmentIndex = 0;
	long addend = 0;

	protected AbstractDyldInfoState(MachHeader header, Program program) {
		this.header = header;
		this.program = program;
	}

	abstract public String print();

	final public void perform(TaskMonitor monitor) throws Exception {
//		if ( SystemUtilities.isInDevelopmentMode() ) {
//			System.out.println( print( ) );
//		}

		monitor.setMessage("Performing bind: " + symbolName);

		Symbol symbol = getSymbol();
		if (symbol == null) {
			return;
		}

		long offset = symbol.getAddress().getOffset();

		DataConverter converter = DataConverter.getInstance(program.getLanguage().isBigEndian());

		byte[] bytes = (program.getDefaultPointerSize() == 8) ? converter.getBytes(offset)
				: converter.getBytes((int) offset);

		Address address = getAddress();

		byte[] originalBytes = new byte[bytes.length];
		program.getMemory().getBytes(address, originalBytes);

		program.getMemory().setBytes(address, bytes);

		//ReferenceManager referenceManager = program.getReferenceManager();
		//Reference reference = referenceManager.addMemoryReference( address, symbol.getAddress(), RefType.READ, SourceType.IMPORTED, 0 );
		//referenceManager.setPrimary( reference, true );
	}

	private Symbol getSymbol() {
		SymbolIterator symbolIterator = program.getSymbolTable().getSymbols(symbolName);
		if (symbolIterator.hasNext()) {
			return symbolIterator.next();
		}
		return null;
	}

	protected Address getAddress() {
		long result = getSegmentStartAddress() + segmentOffset;//TODO
		AddressFactory factory = program.getAddressFactory();
		AddressSpace space = factory.getDefaultAddressSpace();
		if (program.getDefaultPointerSize() == 8) {
			return space.getAddress(result);
		}
		return space.getAddress(result & 0xffffffffL);
	}

	protected String getTypeName() {
		switch (type) {
			case DyldInfoCommandConstants.BIND_TYPE_POINTER: {
				return "pointer";
			}
			case DyldInfoCommandConstants.BIND_TYPE_TEXT_ABSOLUTE32: {
				return "text_absolute32";
			}
			case DyldInfoCommandConstants.BIND_TYPE_TEXT_PCREL32: {
				return "text_pcrel32";
			}
		}
		throw new RuntimeException("unknown dyld info type: " + Integer.toHexString(type));
	}

	protected String getOrdinalName() {
		switch (libraryOrdinal) {
			case DyldInfoCommandConstants.BIND_SPECIAL_DYLIB_SELF: {
				return "this-image";
			}
			case DyldInfoCommandConstants.BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: {
				return "main-executable";
			}
			case DyldInfoCommandConstants.BIND_SPECIAL_DYLIB_FLAT_LOOKUP: {
				return "flat-namespace";
			}
		}
		if (libraryOrdinal < DyldInfoCommandConstants.BIND_SPECIAL_DYLIB_FLAT_LOOKUP) {
			return "unknown dyld info special ordinal" + Integer.toHexString(libraryOrdinal);
		}
		List<DynamicLibraryCommand> dylibCommands =
			header.getLoadCommands(DynamicLibraryCommand.class);
		if (libraryOrdinal > dylibCommands.size()) {
			return "dyld info library ordinal out of range" + Integer.toHexString(libraryOrdinal);
		}
		DynamicLibraryCommand dylibCommand = dylibCommands.get(libraryOrdinal - 1);
		DynamicLibrary dynamicLibrary = dylibCommand.getDynamicLibrary();
		LoadCommandString name = dynamicLibrary.getName();
		return name.getString();
	}

	protected long getSegmentStartAddress() {
		List<SegmentCommand> segments = header.getLoadCommands(SegmentCommand.class);
		SegmentCommand segment = segments.get(segmentIndex);
		return segment.getVMaddress();
	}

	protected String getSegmentName() {
		List<SegmentCommand> segments = header.getLoadCommands(SegmentCommand.class);
		SegmentCommand segment = segments.get(segmentIndex);
		return segment.getSegmentName();
	}

}
