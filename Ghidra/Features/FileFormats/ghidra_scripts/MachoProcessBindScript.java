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
//Processes Mach-O BIND information.
//@category Mac OS X

import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.List;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.Section;
import ghidra.app.util.bin.format.macho.commands.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.util.*;

public class MachoProcessBindScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		File file = new File( currentProgram.getExecutablePath() );
		if ( !file.exists() ) {
			file = askFile( "Please select original file used to import this program:", "Original File" );
		}
		if (file == null) {
			popup("File cannot be null");
			return;
		}
		if ( !file.exists() ) {
			popup( "Cannot find original binary at \n" + file.getAbsolutePath() );
			return;
		}
		ByteProvider provider = new RandomAccessByteProvider( file ) ;
		try {
			MachHeader header = MachHeader.createMachHeader( RethrowContinuesFactory.INSTANCE, provider );
			if ( header == null ) {
				popup( "unable to create mach header from original file" );
				return;
			}
			header.parse();
			List<DyldInfoCommand> commands = header.getLoadCommands( DyldInfoCommand.class );
			for ( DyldInfoCommand command : commands ) {
				if ( monitor.isCancelled() ) {
					break;
				}
				processCommand( header, provider, command );
			}
		}
		finally {
			provider.close();
		}
	}

	private void processCommand( MachHeader header, ByteProvider provider, DyldInfoCommand command ) throws Exception {

		BindState bind = new BindState();
		bind.header = header;

		try {
			boolean done = false;
			
			byte [] commandBytes = provider.readBytes( command.getBindOffset(), command.getBindSize() );
			ByteArrayInputStream byteServer = new ByteArrayInputStream( commandBytes );

			while ( !done ) {

				if ( monitor.isCancelled() ) {
					break;
				}

				int value = byteServer.read();

				if ( value == -1 ) {
					break;
				}

				byte b = (byte) value;

				int opcode    = b & DyldInfoCommandConstants.BIND_OPCODE_MASK;
				int immediate = b & DyldInfoCommandConstants.BIND_IMMEDIATE_MASK;

				switch ( opcode ) {
					case DyldInfoCommandConstants.BIND_OPCODE_ADD_ADDR_ULEB: {
						bind.segmentOffset += uleb128( byteServer );
						break;
					}
					case DyldInfoCommandConstants.BIND_OPCODE_DO_BIND: {
						bind.doBind();
						bind.segmentOffset += currentProgram.getDefaultPointerSize();
						break;
					}
					case DyldInfoCommandConstants.BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
						bind.doBind();
						bind.segmentOffset += ( immediate * currentProgram.getDefaultPointerSize() ) + currentProgram.getDefaultPointerSize();
						break;
					}
					case DyldInfoCommandConstants.BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
						bind.doBind();
						bind.segmentOffset += uleb128( byteServer ) + currentProgram.getDefaultPointerSize();
						break;
					}
					case DyldInfoCommandConstants.BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
						long count = uleb128( byteServer );
						long skip  = uleb128( byteServer );
						for ( int i = 0 ; i < count ; ++i ) {
							bind.doBind();
							bind.segmentOffset += skip + currentProgram.getDefaultPointerSize();
						}
						break;
					}
					case DyldInfoCommandConstants.BIND_OPCODE_DONE: {
						done = true;
						break;
					}
					case DyldInfoCommandConstants.BIND_OPCODE_SET_ADDEND_SLEB: {
						bind.addend = sleb128( byteServer );
						break;
					}
					case DyldInfoCommandConstants.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: {
						bind.libraryOrdinal = immediate;
						bind.fromDylib = getOrdinalName( bind );
						break;
					}
					case DyldInfoCommandConstants.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: {
						bind.libraryOrdinal = (int) uleb128( byteServer );
						bind.fromDylib = getOrdinalName( bind );
						break;
					}
					case DyldInfoCommandConstants.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: {
						//the special ordinals are negative numbers
						if ( immediate == 0 ) {
							bind.libraryOrdinal = 0;
						}
						else {
							byte signExtended = (byte) ( DyldInfoCommandConstants.BIND_OPCODE_MASK | immediate );
							bind.libraryOrdinal = signExtended;
						}
						bind.fromDylib = getOrdinalName( bind );
						break;
					}
					case DyldInfoCommandConstants.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: {
						bind.segmentIndex = immediate;
						bind.segmentStartAddress = getSegmentStartAddress( bind );
						bind.segmentName = getSegmentName( bind );
						bind.segmentOffset = uleb128( byteServer );
						break;
					}
					case DyldInfoCommandConstants.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: {
						bind.symbolName = readString( byteServer );
						if ( ( immediate & DyldInfoCommandConstants.BIND_SYMBOL_FLAGS_WEAK_IMPORT ) != 0 ) {
							bind.weak = true;
						}
						else {
							bind.weak = false;
						}
						break;
					}
					case DyldInfoCommandConstants.BIND_OPCODE_SET_TYPE_IMM: {
						bind.type = immediate;
						bind.typeName = getTypeName( bind );
						break;
					}
					default: {
						popup( "unknown bind opcode " + Integer.toHexString( opcode ) );
						return;
					}
				}
			}
		}
		finally {
		}		
	}

	private String readString( ByteArrayInputStream byteServer ) {
		StringBuffer buffer = new StringBuffer();
		while ( !monitor.isCancelled() ) {
			int value = byteServer.read();
			if ( value == -1 ) {
				break;
			}
			byte b = (byte) value;
			if ( b == '\0' ) {
				break;
			}
			buffer.append( (char) ( b & 0xff ) );
		}
		System.out.println( buffer.toString() );
		return buffer.toString();
	}

	private long getSegmentStartAddress( BindState bind )  {
		List<SegmentCommand> segments = bind.header.getLoadCommands( SegmentCommand.class );
		SegmentCommand segment = segments.get( bind.segmentIndex );
		return segment.getVMaddress();
	}

	private String getSegmentName( BindState bind )  {
		List<SegmentCommand> segments = bind.header.getLoadCommands( SegmentCommand.class );
		SegmentCommand segment = segments.get( bind.segmentIndex );
		return segment.getSegmentName();
	}

	private String getTypeName( BindState bind ) {
		switch ( bind.type ) {
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
		throw new RuntimeException( "unknown type: " + Integer.toHexString( bind.type ) );
	}

	private String getOrdinalName( BindState bind ) {
		switch ( bind.libraryOrdinal ) {
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
		if ( bind.libraryOrdinal < DyldInfoCommandConstants.BIND_SPECIAL_DYLIB_FLAT_LOOKUP ) {
			return "unknown special ordinal" + Integer.toHexString( bind.libraryOrdinal );
		}
		List<DynamicLibraryCommand> dylibCommands = bind.header.getLoadCommands( DynamicLibraryCommand.class );
		if ( bind.libraryOrdinal > dylibCommands.size() ) {
			return "library ordinal out of range" + Integer.toHexString( bind.libraryOrdinal );
		}
		DynamicLibraryCommand dylibCommand = dylibCommands.get( bind.libraryOrdinal - 1 );
		DynamicLibrary dynamicLibrary = dylibCommand.getDynamicLibrary();
		LoadCommandString name = dynamicLibrary.getName();
		return name.getString();
	}

	/**
	 * Unsigned Little-endian Base-128
	 */
	private long uleb128( ByteArrayInputStream byteServer ) throws Exception {
		long result = 0;
		int  bit    = 0;

		while ( !monitor.isCancelled() ) {

			int value = byteServer.read();

			if ( value == -1 ) {
				break;
			}

			byte b = (byte) value;

			long slice = b & 0x7f;

			if ( ( b & 0x80 ) == 0x80 ) {//if upper bit is set
				if ( bit >= 64 || slice << bit >> bit != slice ) {//then left shift and right shift
					throw new RuntimeException( "uleb128 too big" );
				}
			}

			result |= ( slice << bit );
			bit += 7;

			if ( ( b & 0x80 ) == 0 ) {//if upper bit NOT set, then we are done
				break;
			}
		}
		return result;
	}

	/**
	 * Signed Little-endian Base-128
	 */
	private long sleb128( ByteArrayInputStream byteServer ) throws Exception {
		long result = 0;
		int  bit    = 0;
		while ( !monitor.isCancelled() ) {

			int value = byteServer.read();

			if ( value == -1 ) {
				break;
			}

			byte nextByte = (byte) value;

			result |= ( ( nextByte & 0x7f ) << bit );
			bit += 7;

			if ( ( nextByte & 0x80 ) == 0 ) {
				break;
			}
		}
		return result;
	}

	class BindState {
		int count = 0;

		MachHeader header;
		String symbolName;
		String fromDylib;
		int type = 0;
		String typeName;
		int libraryOrdinal = 0;
		long addend = 0;

		String segmentName;
		long segmentStartAddress;
		long segmentOffset = 0;
		int segmentIndex = 0;

		boolean weak = false;

		String print() {
			++count;

			Address sectionAddress = getAddress();

			String sectionName = "no section";
			List<Section> sections = header.getAllSections();
			for ( Section section : sections ) {
				long start = section.getAddress();
				long end   = section.getAddress() + section.getSize();
				if ( sectionAddress.getOffset()  >= start && sectionAddress.getOffset() < end ) {
					sectionName = section.getSectionName();
				}
			}

			File file = new File( fromDylib );

			StringBuffer buffer = new StringBuffer();
			buffer.append(  segmentName );
			buffer.append( ' ' );
			buffer.append( ' ' );
			buffer.append(StringUtilities.pad(sectionName, ' ', -20));
			buffer.append( ' ' );
			buffer.append( ' ' );
			buffer.append( sectionAddress );
			buffer.append( ' ' );
			buffer.append( ' ' );
			buffer.append( typeName );
			buffer.append( ' ' );
			buffer.append( ' ' );
			buffer.append( weak );
			buffer.append( ' ' );
			buffer.append( ' ' );
			buffer.append( addend );
			buffer.append( ' ' );
			buffer.append( ' ' );
			buffer.append(StringUtilities.pad(file.getName(), ' ', -20));
			buffer.append( ' ' );
			buffer.append( ' ' );
			buffer.append( symbolName );
			buffer.append( ' ' );
			buffer.append( ' ' );
			return buffer.toString();
		}

		void doBind() throws Exception {
			monitor.setMessage( "Performing bind: " + symbolName );

			SymbolIterator symbolIterator = currentProgram.getSymbolTable().getSymbols( symbolName );

			if ( !symbolIterator.hasNext() ) {
				printerr( "Not found: " + symbolName );
				return;
			}

			Symbol symbol = symbolIterator.next();

			long offset = symbol.getAddress().getOffset();

			DataConverter converter = DataConverter.getInstance(currentProgram.getLanguage().isBigEndian());

			if ( currentProgram.getDefaultPointerSize() == 8 ) {
				setBytes( getAddress(), converter.getBytes( offset ) );
			}
			else {
				setBytes( getAddress(), converter.getBytes( (int)offset ) );
			}

			Reference reference = currentProgram.getReferenceManager().addMemoryReference( getAddress(), symbol.getAddress(), RefType.READ, SourceType.IMPORTED, 0 );
			currentProgram.getReferenceManager().setPrimary( reference, true );
		}

		Address getAddress() {
			long result = segmentStartAddress + segmentOffset;//TODO
			Address sectionAddress = toAddr( result & 0xffffffffL );
			return sectionAddress;
		}
	}
}
