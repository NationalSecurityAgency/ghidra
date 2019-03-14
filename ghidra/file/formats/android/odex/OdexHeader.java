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
package ghidra.file.formats.android.odex;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class OdexHeader implements StructConverter {

	private byte [] magic;
	private int dexOffset;
	private int dexLength;
	private int depsOffset;
	private int depsLength;
	private int auxOffset;
	private int auxLength;
	private int flags;
	private int padding;
	
	public OdexHeader( BinaryReader reader ) throws IOException {
		magic = reader.readNextByteArray( OdexConstants.ODEX_MAGIC_LENGTH );
		dexOffset = reader.readNextInt();
		dexLength = reader.readNextInt();
		depsOffset = reader.readNextInt();
		depsLength = reader.readNextInt();
		auxOffset = reader.readNextInt();
		auxLength = reader.readNextInt();
		flags = reader.readNextInt();
		padding = reader.readNextInt();
	}

	public String getMagic() {
		return new String( magic );
	}
	/**
	 * Returns byte offset to the optimized DEX file.
	 */
	public int getDexOffset() {
		return dexOffset;
	}
	/**
	 * Returns byte length of the optimized DEX file.
	 */
	public int getDexLength() {
		return dexLength;
	}
	/**
	 * Return byte offset to the framework dependencies.
	 */
	public int getDepsOffset() {
		return depsOffset;
	}
	/**
	 * Return byte length of the framework dependencies.
	 */
	public int getDepsLength() {
		return depsLength;
	}
	/**
	 * Return byte offset to the auxiliary data.
	 */
	public int getAuxOffset() {
		return auxOffset;
	}
	/**
	 * Return byte length to the auxiliary data.
	 */
	public int getAuxLength() {
		return auxLength;
	}
	/**
	 * Return the ODEX flags.
	 */
	public int getFlags() {
		return flags;
	}
	public int getPadding() {
		return padding;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "odex_header_item", 0 );
		structure.add( UTF8, OdexConstants.ODEX_MAGIC_LENGTH, "magic", null );
		structure.add( DWORD, "dex_offset", null );
		structure.add( DWORD, "dex_length", null );
		structure.add( DWORD, "deps_offset", null );
		structure.add( DWORD, "deps_length", null );
		structure.add( DWORD, "aux_offset", null );
		structure.add( DWORD, "aux_length", null );
		structure.add( DWORD, "flags", null );
		structure.add( DWORD, "padding", null );
		return structure;
	}

}
