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
package pdb.symbolserver;

import java.util.Map;
import java.util.Objects;

import java.io.File;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.format.pdb.PdbParserConstants;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbIdentifiers;
import ghidra.app.util.datatype.microsoft.GUID;
import ghidra.util.task.TaskMonitor;
import pdb.PdbUtils;

/**
 * Information about a pdb symbol file: its filename and its 
 * {@link PdbIdentifiers pdb guid/id fingerprints}
 * 
 */
public class SymbolFileInfo {
	private static final int MIN_SIG_HEX_STR_LEN = 8;
	private static final int GUID_HEX_STR_LEN = 32;

	/**
	 * Create a SymbolFileInfo instance that represents an unknown / bad
	 * file.
	 * 
	 * @param path path string to use
	 * @return new SymbolFileInfo with a PdbIdentifier with bogus / default values
	 */
	public static SymbolFileInfo unknown(String path) {
		return new SymbolFileInfo(path, new PdbIdentifiers(0, 0, 0, null, null));
	}

	/**
	 * Create a SymbolFileInfo instance from the metadata found in a program
	 *  
	 * @param metadata Map of String-to-String values taken from a program
	 * @return new SymbolFileInfo instance, or null if no Pdb info found
	 */
	public static SymbolFileInfo fromMetadata(Map<String, String> metadata) {
		try {
			int sig =
				Integer.parseUnsignedInt(
					metadata.getOrDefault(PdbParserConstants.PDB_SIGNATURE, "0"), 16);
			String guidString = metadata.getOrDefault(PdbParserConstants.PDB_GUID, "");
			GUID guid = (guidString != null && !guidString.isBlank()) ? new GUID(guidString) : null;
			int age = Integer
					.parseUnsignedInt(metadata.getOrDefault(PdbParserConstants.PDB_AGE, "0"), 16);
			String path = metadata.getOrDefault(PdbParserConstants.PDB_FILE, "<unknown>");

			PdbIdentifiers pdbIdentifiers = new PdbIdentifiers(0, sig, age, guid, null);

			return new SymbolFileInfo(path, pdbIdentifiers);
		}
		catch (IllegalArgumentException e) {
			return null;
		}
	}

	/**
	 * Create a new {@link SymbolFileInfo} instance using information scraped from a pdb symbol
	 * server subdir path.
	 * 
	 * @param path name of the pdb file
	 * @param uniqueSubdir string that is a combo of 32_hexchar_GUID + age or 
	 * 8_hexchar_signature + age
	 * @return new {@link SymbolFileInfo} instance, or null if invalid info in path
	 * or subdir names
	 */
	public static SymbolFileInfo fromSubdirectoryPath(String path, String uniqueSubdir) {
		try {
			if (MIN_SIG_HEX_STR_LEN < uniqueSubdir.length() &&
				uniqueSubdir.length() < GUID_HEX_STR_LEN) {
				int sig = Integer.parseUnsignedInt(uniqueSubdir.substring(0, 8), 16);
				int age = Integer.parseUnsignedInt(uniqueSubdir.substring(8), 16);

				return new SymbolFileInfo(path, new PdbIdentifiers(0, sig, age, null, null));
			}
			else if (uniqueSubdir.length() > GUID_HEX_STR_LEN) {
				String guidString = uniqueSubdir.substring(0, GUID_HEX_STR_LEN);
				GUID guid = new GUID(guidString);

				int age = Integer.parseUnsignedInt(uniqueSubdir.substring(GUID_HEX_STR_LEN), 16);

				return new SymbolFileInfo(path, new PdbIdentifiers(0, 0, age, guid, null));
			}

		}
		catch (IllegalArgumentException e) {
			// ignore
		}
		return null;
	}

	/**
	 * Creates a new instance using the specified path and guid/id string and age.
	 * 
	 * @param path String pdb path filename
	 * @param uid String GUID or signature id
	 * @param age int value
	 * @return new {@link SymbolFileInfo} instance made of specified path and identity info,
	 * or null if bad GUID / signature id string
	 */
	public static SymbolFileInfo fromValues(String path, String uid, int age) {
		try {
			GUID guid = new GUID(uid);
			return new SymbolFileInfo(path, new PdbIdentifiers(0, 0, age, guid, null));
		}
		catch (IllegalArgumentException e) {
			// ignore, try older codeview
		}
		try {
			int sig = Integer.parseUnsignedInt(uid, 16);
			return new SymbolFileInfo(path, new PdbIdentifiers(0, sig, age, null, null));
		}
		catch (IllegalArgumentException e) {
			// fail
		}
		return null;
	}

	/**
	 * Create a new instance using the specified path and {@link PdbIdentifiers}.
	 * 
	 * @param path String pdb path filename
	 * @param pdbIdent {@link PdbIdentifiers}
	 * @return new {@link SymbolFileInfo} instance made of specified path and ident info
	 */
	public static SymbolFileInfo fromPdbIdentifiers(String path, PdbIdentifiers pdbIdent) {
		return new SymbolFileInfo(path, pdbIdent);
	}

	/**
	 * Create a new instance using the information found inside the specified file.
	 * <p>
	 * The file will be opened and parsed to determine its GUID/ID and age.
	 * 
	 * @param pdbFile pdb file to create a SymbolFileInfo for
	 * @param monitor {@link TaskMonitor} for progress and cancel
	 * @return new {@link SymbolFileInfo} instance or null if file is not a valid pdb or pdb.xml
	 * file
	 */
	public static SymbolFileInfo fromFile(File pdbFile, TaskMonitor monitor) {
		PdbIdentifiers pdbIdentifiers = PdbUtils.getPdbIdentifiers(pdbFile, monitor);
		return (pdbIdentifiers != null) ? new SymbolFileInfo(pdbFile.getName(), pdbIdentifiers)
				: null;
	}

	private final PdbIdentifiers pdbIdentifiers;
	private final String pdbPath;

	private SymbolFileInfo(String pdbPath, PdbIdentifiers pdbIdentifiers) {
		this.pdbPath = pdbPath;
		this.pdbIdentifiers = pdbIdentifiers;
	}

	/**
	 * Returns the {@link PdbIdentifiers} of this instance.
	 * 
	 * @return {@link PdbIdentifiers} of this instance
	 */
	public PdbIdentifiers getIdentifiers() {
		return pdbIdentifiers;
	}

	/**
	 * The name of the pdb file, derived from the {@link #getPath() path} value.
	 * 
	 * @return String name of the pdb file
	 */
	public String getName() {
		return FilenameUtils.getName(pdbPath);
	}

	/**
	 * The 'path' of the pdb file, which contains the full path and filename recovered from the 
	 * original binary's debug data.  Typically, this is just a plain name string without any
	 * path info.
	 * 
	 * @return original pdb path string recovered from binary's debug data
	 */
	public String getPath() {
		return pdbPath;
	}

	/**
	 * A string that represents the unique fingerprint of a Pdb file.  Does not
	 * include the age.
	 * 
	 * @return either GUID str or signature hexstring
	 */
	public String getUniqueName() {
		return (pdbIdentifiers.getGuid() != null)
				? pdbIdentifiers.getGuid().toString().replace("-", "").toUpperCase()
				: String.format("%08X", pdbIdentifiers.getSignature());

	}

	/**
	 * Returns a string that is a combination of the GUID/ID and the age, in a format
	 * used by symbol servers to create subdirectories in their directory structure.
	 * 
	 * @return String combination of GUID/ID and age, e.g. "112233441"
	 */
	public String getUniqueDirName() {
		return getUniqueName() + Integer.toUnsignedString(pdbIdentifiers.getAge(), 16);
	}

	/**
	 * Returns true if this SymbolFileInfo instance exactly matches the {@link PdbIdentifiers}
	 * info of the other instance.
	 *  
	 * @param other {@link SymbolFileInfo} to compare
	 * @return boolean true if exact match of {@link PdbIdentifiers} info
	 */
	public boolean isExactMatch(SymbolFileInfo other) {
		return getUniqueName().equalsIgnoreCase(other.getUniqueName()) &&
			pdbIdentifiers.getAge() == other.getIdentifiers().getAge();
	}

	/**
	 * Returns a description of this instance.
	 * 
	 * @return String description
	 */
	public String getDescription() {
		return getName() + ", " + getIdentifiers();
	}

	@Override
	public String toString() {
		return String.format("SymbolFileInfo: [ pdb: %s, uid: %s]", getName(),
			getIdentifiers().toString());
	}

	@Override
	public int hashCode() {
		return Objects.hash(pdbIdentifiers, pdbPath);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SymbolFileInfo other = (SymbolFileInfo) obj;
		return Objects.equals(pdbIdentifiers, other.pdbIdentifiers) &&
			Objects.equals(pdbPath, other.pdbPath);
	}

}
