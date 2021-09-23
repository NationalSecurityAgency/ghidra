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
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;

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

	protected OatHeader(BinaryReader reader) throws IOException {
		magic = new String(reader.readNextByteArray(OatConstants.MAGIC.length()));
		version = reader.readNextAsciiString(4);
	}

	/**
	 * Parses the OAT header beyond the MAGIC and VERSION fields.
	 * The "additionalData" is used to future proof the parsers.
	 * For example, its needed for handling vdex files.
	 */
	abstract public void parse(BinaryReader reader, Object additionalData)
			throws IOException, UnsupportedOatVersionException;

	/**
	 * Returns the MAGIC string, i.e. "oat\n".
	 */
	public String getMagic() {
		return magic;
	}

	/**
	 * Returns the VERSION string, e.g. "001", "009", etc.
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * Returns the number of DEX files embedded inside this OAT file.
	 */
	abstract public int getDexFileCount();

	/**
	 * Returns the size (in bytes) of the Key/Value store contained inside this OAT file.
	 */
	abstract public int getKeyValueStoreSize();

	/**
	 * Returns a list of the OatDexFileHeader, a structure defining the embedded DEX files.
	 */
	abstract public List<OatDexFile> getOatDexFileList();

	/**
	 * Returns the OAT instruction set (ARM, X86, etc).
	 */
	abstract public OatInstructionSet getInstructionSet();

	/**
	 * Returns the offset to the executable code, relative to the "oatdata" symbol.
	 * The executable code can also be located using the "oatexec" symbol.
	 */
	abstract public int getExecutableOffset();

	/**
	 * Returns the OAT checksum value.
	 */
	abstract public int getChecksum();
}
