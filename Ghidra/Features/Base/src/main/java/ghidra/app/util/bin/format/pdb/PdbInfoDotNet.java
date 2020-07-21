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
package ghidra.app.util.bin.format.pdb;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.pe.debug.DebugCodeViewConstants;
import ghidra.app.util.datatype.microsoft.GUID;
import ghidra.app.util.datatype.microsoft.GuidDataType;
import ghidra.framework.options.Options;
import ghidra.program.model.data.*;

/**
 * Newer style pdb information, using a GUID to link the pdb to its binary.
 */
public class PdbInfoDotNet implements StructConverter, PdbInfo {
	private static final int MAGIC =
		DebugCodeViewConstants.SIGNATURE_DOT_NET << 16 | DebugCodeViewConstants.VERSION_DOT_NET;

	/**
	 * Returns true if the pdb information at the specified offset is a {@link PdbInfoDotNet}
	 * type (based on the signature at that offset).
	 * 
	 * @param reader {@link BinaryReader}
	 * @param offset offset of the Pdb information
	 * @return boolean true if it is a {@link PdbInfoDotNet} type
	 * @throws IOException if error reading data
	 */
	public static boolean isMatch(BinaryReader reader, long offset) throws IOException {
		//read value out as big endian
		int value = reader.asBigEndian().readInt(offset);
		return MAGIC == value;
	}

	/**
	 * Reads an instance from the stream.
	 * 
	 * @param reader {@link BinaryReader} to read from
	 * @param offset position of the pdb info
	 * @return new instance, never null
	 * @throws IOException if IO error or data format error
	 */
	public static PdbInfoDotNet read(BinaryReader reader, long offset) throws IOException {
		reader = reader.clone(offset);

		PdbInfoDotNet result = new PdbInfoDotNet();
		result.magic = reader.readNextByteArray(4);
		result.guid = new GUID(reader);
		result.age = reader.readNextInt();
		result.pdbPath = reader.readNextAsciiString();
		result.pdbName = FilenameUtils.getName(result.pdbPath);

		return result;
	}

	/**
	 * Creates an instance from explicit values.
	 * 
	 * @param pdbPath String path / filename of the pdb file
	 * @param age age
	 * @param guid {@link GUID}
	 * @return new instance, never null
	 */
	public static PdbInfoDotNet fromValues(String pdbPath, int age, GUID guid) {
		PdbInfoDotNet result = new PdbInfoDotNet();
		result.pdbPath = pdbPath;
		result.pdbName = FilenameUtils.getName(result.pdbPath);
		result.age = age;
		result.guid = guid;
		result.magic = "????".getBytes();

		return result;
	}


	private byte[] magic;
	private GUID guid;
	private int age;
	private String pdbName;
	private String pdbPath;

	private PdbInfoDotNet() {
		// empty
	}

	@Override
	public boolean isValid() {
		return magic.length == 4 && !pdbName.isBlank() && guid != null;
	}

	@Override
	public void serializeToOptions(Options options) {
		options.setString(PdbParserConstants.PDB_VERSION,
			new String(magic, StandardCharsets.US_ASCII));
		options.setString(PdbParserConstants.PDB_GUID, guid.toString());
		options.setString(PdbParserConstants.PDB_AGE, Integer.toHexString(age));
		options.setString(PdbParserConstants.PDB_FILE, pdbName);
	}

	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType("DotNetPdbInfo", 0);
		struct.add(new StringDataType(), magic.length, "signature", null);
		struct.add(new GuidDataType(), "guid", null);
		struct.add(new DWordDataType(), "age", null);
		if (pdbName.length() > 0) {
			struct.add(new StringDataType(), pdbName.length(), "pdbname", null);
		}
		struct.setCategoryPath(new CategoryPath("/PDB"));
		return struct;
	}

}
