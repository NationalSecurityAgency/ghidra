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
import ghidra.framework.options.Options;
import ghidra.program.model.data.*;
import ghidra.util.Conv;

/**
 * Older style pdb information, using a simple 32bit hash to link the pdb to its binary.
 */
public class PdbInfoCodeView implements StructConverter, PdbInfo {
	private static final int MAGIC =
		DebugCodeViewConstants.SIGNATURE_NB << 16 | DebugCodeViewConstants.VERSION_10;

	/**
	 * Returns true if the pdb information at the specified offset is a {@link PdbInfoCodeView}
	 * type (based on the signature at that offset).
	 * 
	 * @param reader {@link BinaryReader}
	 * @param offset offset of the Pdb information
	 * @return boolean true if it is a {@link PdbInfoCodeView} type
	 * @throws IOException if error reading data
	 */
	public static boolean isMatch(BinaryReader reader, long offset) throws IOException {
		//read value out as big endian
		int value = reader.asBigEndian().readInt(offset);
		return MAGIC == value;
	}

	/**
	 * Reads the pdb information from a PE binary.
	 * 
	 * @param reader {@link BinaryReader}
	 * @param offset offset of the Pdb information
	 * @return new {@link PdbInfoCodeView} instance, never null
	 * @throws IOException if error reading data
	 */
	public static PdbInfoCodeView read(BinaryReader reader, long offset) throws IOException {
		reader = reader.clone(offset);

		PdbInfoCodeView result = new PdbInfoCodeView();
		result.magic = reader.readNextByteArray(4);
		result.offset = reader.readNextInt();
		result.sig = reader.readNextInt();
		result.age = reader.readNextInt();
		result.pdbPath = reader.readNextAsciiString();
		result.pdbName = FilenameUtils.getName(result.pdbPath);

		return result;
	}

	private byte[] magic;
	private int offset;
	private int sig;
	private int age;
	private String pdbName;
	private String pdbPath;

	private PdbInfoCodeView() {
		// nothing
	}

	@Override
	public boolean isValid() {
		return magic.length == 4 && !pdbName.isBlank();
	}

	@Override
	public void serializeToOptions(Options options) {
		options.setString(PdbParserConstants.PDB_VERSION,
			new String(magic, StandardCharsets.US_ASCII));
		options.setString(PdbParserConstants.PDB_SIGNATURE, Conv.toHexString(sig));
		options.setString(PdbParserConstants.PDB_AGE, Integer.toHexString(age));
		options.setString(PdbParserConstants.PDB_FILE, pdbName);
	}

	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType("PdbInfo", 0);
		struct.add(new StringDataType(), magic.length, "signature", null);
		struct.add(new DWordDataType(), "offset", null);
		struct.add(new DWordDataType(), "sig", null);
		struct.add(new DWordDataType(), "age", null);
		if (pdbName.length() > 0) {
			struct.add(new StringDataType(), pdbName.length(), "pdbname", null);
		}
		struct.setCategoryPath(new CategoryPath("/PDB"));
		return struct;
	}

}
