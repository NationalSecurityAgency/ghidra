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
package ghidra.file.formats.android.dex.format;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.*;

/**
 * code_item
 * 
 * referenced from encoded_method
 * 
 * appears in the data section
 * 
 * alignment: 4 bytes
 */
public class CodeItem implements StructConverter {

	private short registersSize;
	private short incomingSize;
	private short outgoingSize;
	private short triesSize;
	private int debugInfoOffset;
	private int instructionSize;
	private short [] instructions;
	private byte [] instructionBytes;
	private short padding;
	private List< TryItem > tries = new ArrayList< TryItem >( );
	private EncodedCatchHandlerList handlers;
	private DebugInfoItem debugInfo;

	public CodeItem( BinaryReader reader ) throws IOException {
		registersSize = reader.readNextShort( );
		incomingSize = reader.readNextShort( );
		outgoingSize = reader.readNextShort( );
		triesSize = reader.readNextShort( );
		debugInfoOffset = reader.readNextInt( );
		instructionSize = reader.readNextInt( );
		if ( instructionSize == 0 ) {
			instructionBytes = new byte[ 0 ];
			instructions = new short[ 0 ];
		}
		else {
			instructionBytes = reader.readByteArray( reader.getPointerIndex( ), instructionSize * 2 );
			instructions = reader.readNextShortArray( instructionSize );
		}
		if ( hasPadding( ) ) {
			padding = reader.readNextShort( );
		}
		for ( int i = 0 ; i < triesSize ; ++i ) {
			tries.add( new TryItem( reader ) );
		}
		if ( triesSize > 0 ) {
			handlers = new EncodedCatchHandlerList( reader );
		}

		if ( debugInfoOffset > 0 ) {
			long oldIndex = reader.getPointerIndex( );
			try {
				reader.setPointerIndex( debugInfoOffset );
				debugInfo = new DebugInfoItem( reader );
			}
			finally {
				reader.setPointerIndex( oldIndex );
			}
		}
	}

	/**
	 * <pre>
	 * The number of registers used by this code
	 * </pre>
	 */
	public short getRegistersSize( ) {
		return registersSize;
	}

	/**
	 * <pre>
	 * The number of words of incoming arguments to the method that this code is for
	 * </pre>
	 */
	public short getIncomingSize( ) {
		return incomingSize;
	}

	/**
	 * <pre>
	 * The number of words of outgoing argument space required by this code for method invocation
	 * </pre>
	 */
	public short getOutgoingSize( ) {
		return outgoingSize;
	}

	/**
	 * <pre>
	 * The number of try_items for this instance. 
	 * If non-zero, then these appear as the tries array just 
	 * after the insns in this instance.
	 * </pre>
	 */
	public short getTriesSize( ) {
		return triesSize;
	}

	/**
	 * <pre>
	 * Offset from the start of the file to the debug info 
	 * (line numbers + local variable info) sequence for this code, or 0 if there 
	 * simply is no information. The offset, if non-zero, should be to a location 
	 * in the data section. The format of the data is specified by "debug_info_item" below.
	 * </pre>
	 */
	public int getDebugInfoOffset( ) {
		return debugInfoOffset;
	}

	/**
	 * Size of the instructions list, in 16-bit code units
	 */
	public int getInstructionSize( ) {
		return instructionSize;
	}

	/**
	 * <pre>
	 * Actual array of bytecode. 
	 * The format of code in an insns array is specified by the companion document Dalvik bytecode. 
	 * Note that though this is defined as an array of ushort, 
	 * there are some internal structures that prefer four-byte alignment. 
	 * Also, if this happens to be in an endian-swapped file, then the swapping is 
	 * only done on individual ushorts and not on the larger internal structures.
	 * </pre>
	 */
	public short [] getInstructions( ) {
		return instructions;
	}

	public byte [] getInstructionBytes( ) {
		return instructionBytes;
	}

	/**
	 * <pre>
	 * Two bytes of padding to make tries four-byte aligned. 
	 * This element is only present if tries_size is non-zero and insns_size is odd.
	 * </pre>
	 */
	public short getPadding( ) {
		return padding;
	}

	/**
	 * <pre>
	 * Array indicating where in the code exceptions are caught and how to handle them. 
	 * Elements of the array must be non-overlapping in range and in order from low to high address. 
	 * This element is only present if tries_size is non-zero.
	 * </pre>
	 */
	public List< TryItem > getTries( ) {
		return Collections.unmodifiableList( tries );
	}

	/**
	 * <pre>
	 * Bytes representing a list of lists of catch types and associated handler addresses. 
	 * Each try_item has a byte-wise offset into this structure. 
	 * This element is only present if tries_size is non-zero.
	 * </pre>
	 */
	public EncodedCatchHandlerList getHandlerList( ) {
		return handlers;
	}

	public DebugInfoItem getDebugInfo( ) {
		return debugInfo;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		String suffix = hasPadding( ) ? "_p" : "";
		String name = "code_item" + "_" + ( instructionSize * 2 ) + suffix;
		Structure structure = new StructureDataType( name, 0 );
		structure.add( WORD, "registers_size", null );
		structure.add( WORD, "ins_size", null );
		structure.add( WORD, "outs_size", null );
		structure.add( WORD, "tries_size", null );
		structure.add( DWORD, "debug_info_off", null );
		structure.add( DWORD, "insns_size", null );
		structure.add( new ArrayDataType( WORD, instructionSize, WORD.getLength( ) ), "insns", null );
		if ( hasPadding( ) ) {
			structure.add( WORD, "padding", null );
		}
		// for ( int i = 0 ; i < tries.size( ) ; ++i ) {
		// DataType dataType = tries.get( i ).toDataType( );
		// structure.add( dataType, "tries_" + i, null );
		// unique = dataType.getLength( );
		// }
		// if ( triesSize != 0 ) {
		// DataType dataType = handlers.toDataType( );
		// structure.add( dataType, "handlers", null );
		// unique = dataType.getLength( );
		// }
		structure.setCategoryPath( new CategoryPath( "/dex/code_item" ) );
		return structure;
	}

	private boolean hasPadding( ) {
		return ( instructionSize % 2 ) != 0;
	}
}
