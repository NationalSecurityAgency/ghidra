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
package ghidra.app.util.bin.format.som;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Represents a SOM {@code compilation_unit} structure
 * 
 * @see <a href="https://web.archive.org/web/20050502101134/http://devresource.hp.com/drc/STK/docs/archive/rad_11_0_32.pdf">The 32-bit PA-RISC Run-time Architecture Document</a> 
 */
public class SomCompilationUnit implements StructConverter {

	/** The size in bytes of a {@link SomCompilationUnit} */
	public static final int SIZE = 0x24;

	private String name;
	private String languageName;
	private String productId;
	private String versionId;
	private int reserved;
	private boolean chunkFlag;
	private SomSysClock compileTime;
	private SomSysClock sourceTime;


	/**
	 * Creates a new {@link SomCompilationUnit}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the record
	 * @param symbolStringsLocation The starting index of the symbol strings
	 * @throws IOException if there was an IO-related error
	 */
	public SomCompilationUnit(BinaryReader reader, long symbolStringsLocation) throws IOException {
		name = reader.readAsciiString(symbolStringsLocation + reader.readNextUnsignedInt());
		languageName = reader.readAsciiString(symbolStringsLocation + reader.readNextUnsignedInt());
		productId = reader.readAsciiString(symbolStringsLocation + reader.readNextUnsignedInt());
		versionId = reader.readAsciiString(symbolStringsLocation + reader.readNextUnsignedInt());
		int bitfield = reader.readNextInt();
		chunkFlag = (bitfield & 0x1) != 0;
		reserved = (bitfield >> 1) & 0x7fffffff;
		compileTime = new SomSysClock(reader);
		sourceTime = new SomSysClock(reader);
	}

	/**
	 * {@return the compilation unit name}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return the language name}
	 */
	public String getLanguageName() {
		return languageName;
	}
	
	/**
	 * {@return the product ID}
	 */
	public String getProductId() {
		return productId;
	}

	/**
	 * {@return the version ID}
	 */
	public String getVersionId() {
		return versionId;
	}

	/**
	 * {@return the reserved value}
	 */
	public int getReserved() {
		return reserved;
	}

	/**
	 * {@return whether or not the compilation unit is not the first SOM in a multiple chunk
	 * compilation}
	 */
	public boolean getChunkFlag() {
		return chunkFlag;
	}

	/**
	 * {@return the compile time}
	 */
	public SomSysClock getCompileTime() {
		return compileTime;
	}

	/**
	 * {@return the source time}
	 */
	public SomSysClock getSourceTime() {
		return sourceTime;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("compilation_unit", SIZE);
		struct.setPackingEnabled(true);
		struct.add(DWORD, "name", null);
		struct.add(DWORD, "language_name", null);
		struct.add(DWORD, "product_id", null);
		struct.add(DWORD, "version_id", null);
		try {
			struct.addBitField(DWORD, 31, "reserved", null);
			struct.addBitField(DWORD, 1, "chunk_flag", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}
		struct.add(compileTime.toDataType(), "compile_time", null);
		struct.add(sourceTime.toDataType(), "source_time", null);
		struct.setCategoryPath(new CategoryPath("/SOM"));
		return struct;
	}
}
