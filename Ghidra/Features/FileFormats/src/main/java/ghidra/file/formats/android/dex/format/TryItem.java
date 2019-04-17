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

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * 
 * try_item format
 * 
 */
public class TryItem implements StructConverter {

	private int startAddress;
	private short instructionCount;
	private short handlerOffset;

	TryItem( BinaryReader reader ) throws IOException {
		startAddress = reader.readNextInt( );
		instructionCount = reader.readNextShort( );
		handlerOffset = reader.readNextShort( );
	}

	/**
	 * <pre>
	 * Start address of the block of code covered by this entry. 
	 * The address is a count of 16-bit code units to the start of the first covered instruction.
	 * </pre>
	 */
	public int getStartAddress( ) {
		return startAddress;
	}

	/**
	 * <pre>
	 * Number of 16-bit code units covered by this entry. 
	 * The last code unit covered (inclusive) is start_addr + insn_count - 1.
	 * </pre>
	 */
	public short getInstructionCount( ) {
		return instructionCount;
	}

	/**
	 * <pre>
	 * Offset in bytes from the start of the associated encoded_catch_hander_list to 
	 * the encoded_catch_handler for this entry. 
	 * This must be an offset to the start of an encoded_catch_handler.
	 * </pre>
	 */
	public short getHandlerOffset( ) {
		return handlerOffset;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType( TryItem.class );
		dataType.setCategoryPath( new CategoryPath( "/dex" ) );
		return dataType;
	}

}
