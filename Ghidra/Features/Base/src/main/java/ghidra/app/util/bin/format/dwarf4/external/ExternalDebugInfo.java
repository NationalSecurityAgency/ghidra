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
package ghidra.app.util.bin.format.dwarf4.external;

import ghidra.app.util.bin.format.elf.GnuBuildIdSection;
import ghidra.app.util.bin.format.elf.GnuBuildIdSection.GnuBuildIdValues;
import ghidra.app.util.bin.format.elf.GnuDebugLinkSection;
import ghidra.app.util.bin.format.elf.GnuDebugLinkSection.GnuDebugLinkSectionValues;
import ghidra.program.model.listing.Program;
import ghidra.util.NumericUtilities;

/**
 * Metadata needed to find an ELF/DWARF external debug file, retrieved from an ELF binary's
 * ".gnu_debuglink" section and/or ".note.gnu.build-id" section.  
 * <p>
 * The debuglink can provide a filename and crc of the external debug file, while the build-id
 * can provide a hash that is converted to a filename that identifies the external debug file.
 */
public class ExternalDebugInfo {

	/**
	 * Create a new {@link ExternalDebugInfo} from information found in the specified program.
	 *  
	 * @param program {@link Program} to query
	 * @return new {@link ExternalDebugInfo} or null if no external debug metadata found in
	 * program
	 */
	public static ExternalDebugInfo fromProgram(Program program) {
		GnuDebugLinkSectionValues debugLinkValues = GnuDebugLinkSection.fromProgram(program);
		GnuBuildIdValues buildIdValues = GnuBuildIdSection.fromProgram(program);
		if (buildIdValues != null && !buildIdValues.isValid()) {
			buildIdValues = null;
		}
		if (debugLinkValues == null && buildIdValues == null) {
			return null;
		}

		String filename = debugLinkValues != null ? debugLinkValues.getFilename() : null;
		int crc = debugLinkValues != null ? debugLinkValues.getCrc() : 0;
		byte[] hash = buildIdValues != null ? buildIdValues.getDescription() : null;
		return new ExternalDebugInfo(filename, crc, hash);
	}

	private String filename;
	private int crc;
	private byte[] hash;

	/**
	 * Constructor to create an {@link ExternalDebugInfo} instance.
	 * 
	 * @param filename filename of external debug file, or null
	 * @param crc crc32 of external debug file, or 0 if no filename 
	 * @param hash build-id hash digest found in ".note.gnu.build-id" section, or null if
	 * not present 
	 */
	public ExternalDebugInfo(String filename, int crc, byte[] hash) {
		this.filename = filename;
		this.crc = crc;
		this.hash = hash;
	}

	/**
	 * Return true if there is a filename
	 * 
	 * @return boolean true if filename is available, false if not
	 */
	public boolean hasFilename() {
		return filename != null && !filename.isBlank();
	}

	/**
	 * Return the filename of the external debug file, or null if not specified.
	 * 
	 * @return String filename of external debug file, or null if not specified
	 */
	public String getFilename() {
		return filename;
	}

	/**
	 * Return the crc of the external debug file.  Not valid if filename is missing.
	 * 
	 * @return int crc32 of external debug file.
	 */
	public int getCrc() {
		return crc;
	}

	/**
	 * Return the build-id hash digest.
	 * 
	 * @return byte array containing the build-id hash (usually 20 bytes)
	 */
	public byte[] getHash() {
		return hash;
	}

	@Override
	public String toString() {
		return String.format("ExternalDebugInfo [filename=%s, crc=%s, hash=%s]",
			filename,
			Integer.toHexString(crc),
			NumericUtilities.convertBytesToString(hash));
	}
}
