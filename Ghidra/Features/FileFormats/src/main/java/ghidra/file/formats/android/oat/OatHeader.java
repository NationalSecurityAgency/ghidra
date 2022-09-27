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
package ghidra.file.formats.android.oat;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.android.oat.bundle.OatBundle;
import ghidra.file.formats.android.oat.oatdexfile.OatDexFile;
import ghidra.file.formats.android.oat.oatdexfile.OatDexFileFactory;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * Base OatHeader implementations
 * <br>
 * Each sub-class is based on that version of OAT, as released,
 * and overrides/modifies behavior, as defined in the original source, from the previous version(s).
 * <br>
 * Some versions have no apparent change in class fields.
 */
public abstract class OatHeader implements StructConverter {

	protected String magic;
	protected String version;

	protected List<String> orderedKeyList = new ArrayList<String>();//ordered as defined
	protected Map<String, String> key_value_store_ = new HashMap<String, String>();

	protected List<OatDexFile> oatDexFileList = new ArrayList<OatDexFile>();

	/**
	 * Base constructor for the OAT headers.
	 * @param reader the binary reader with the file bytes.
	 * @throws IOException if an IO exception occurs.
	 */
	protected OatHeader(BinaryReader reader) throws IOException {
		magic = new String(reader.readNextByteArray(OatConstants.MAGIC.length()));
		version = reader.readNextAsciiString(4);
	}

	/**
	 * Parses the OAT header beyond the MAGIC and VERSION fields.
	 * The "additionalData" is used to future proof the parsers.
	 * For example, its needed for handling vdex files.
	 * @param reader the binary reader with the file bytes.
	 * @param bundle the fake OAT bundle containing the DEX, VDEX, etc.
	 * @throws IOException if an IO exception occurs.
	 * @throws UnsupportedOatVersionException if the OAT version is not supported.
	 */
	public void parse(BinaryReader reader, OatBundle bundle)
			throws IOException, UnsupportedOatVersionException {

		int count = 0;
		while (count < getKeyValueStoreSize()) {
			String key = reader.readNextAsciiString();
			String value = reader.readNextAsciiString();
			count += key.length() + 1;
			count += value.length() + 1;
			orderedKeyList.add(key);
			key_value_store_.put(key, value);
		}

		reader.setPointerIndex(getOatDexFilesOffset(reader));
		for (int i = 0; i < getDexFileCount(); ++i) {
			oatDexFileList.add(
				OatDexFileFactory.getOatDexFile(reader, getVersion(), bundle));
		}
	}

	/**
	 * Returns the MAGIC string, i.e. "oat\n".
	 * @return the MAGIC string, i.e. "oat\n".
	 */
	public String getMagic() {
		return magic;
	}

	/**
	 * Returns the VERSION string, e.g. "001", "009", etc.
	 * @return the VERSION string, e.g. "001", "009", etc.
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * Returns the binary offset to the DEX files.
	 * @param reader the binary reader with the file bytes.
	 * @return the binary offset to the DEX files.
	 */
	abstract public int getOatDexFilesOffset(BinaryReader reader);

	/**
	 * Returns the number of DEX files embedded inside this OAT file.
	 * @return the number of DEX files embedded inside this OAT file.
	 */
	abstract public int getDexFileCount();

	/**
	 * Returns the size (in bytes) of the Key/Value store contained inside this OAT file.
	 * @return the size (in bytes) of the Key/Value store contained inside this OAT file.
	 */
	abstract public int getKeyValueStoreSize();

	/**
	 * Returns a list of the OatDexFileHeader, a structure defining the embedded DEX files.
	 * @return a list of the OatDexFileHeader, a structure defining the embedded DEX files.
	 */
	abstract public List<OatDexFile> getOatDexFileList();

	/**
	 * Returns the OAT instruction set (ARM, X86, etc).
	 * @return the OAT instruction set (ARM, X86, etc).
	 */
	abstract public OatInstructionSet getInstructionSet();

	/**
	 * Returns the offset to the executable code.
	 * Relative to the "oatdata" symbol.
	 * The executable code can also be located using the "oatexec" symbol.
	 * @return the offset to the executable code.
	 */
	abstract public int getExecutableOffset();

	/**
	 * Returns the OAT checksum value.
	 * @return the OAT checksum value.
	 */
	abstract public int getChecksum();

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure =
			new StructureDataType(OatHeader.class.getSimpleName() + "_" + version, 0);
		structure.add(STRING, 4, "magic_", null);
		structure.add(STRING, 4, "version_", null);
		structure.setCategoryPath(new CategoryPath("/oat"));
		return structure;
	}
}
