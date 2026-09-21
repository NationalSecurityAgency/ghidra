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
package ghidra.app.util.bin.format.dwarf.external;

import java.util.Objects;

import ghidra.app.util.bin.format.elf.info.GnuDebugLink;
import ghidra.program.model.listing.Program;

/**
 * Represents {@link ExternalDebugInfo} found in a debug-link property embedded in an ELF file.
 */
public class DebugLinkDebugInfo implements ExternalDebugInfo {

	public static DebugLinkDebugInfo fromProgram(Program program) {
		GnuDebugLink debugLink = GnuDebugLink.fromProgram(program);
		return debugLink != null && !debugLink.getFilename().isEmpty()
				? new DebugLinkDebugInfo(debugLink.getFilename(), debugLink.getCrc())
				: null;
	}

	private final String filename;
	private final int crc;

	/**
	 * @param filename filename of external debug file
	 * @param crc crc32 of external debug file 
	 */
	public DebugLinkDebugInfo(String filename, int crc) {
		this.filename = filename;
		this.crc = crc;
	}

	/**
	 * Return the filename of the external debug file
	 * 
	 * @return String filename of external debug file
	 */
	public String getFilename() {
		return filename;
	}

	/**
	 * Return the crc of the external debug file.
	 * 
	 * @return int crc32 of external debug file.
	 */
	public int getCrc() {
		return crc;
	}

	@Override
	public int hashCode() {
		return Objects.hash(Integer.valueOf(crc), filename);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof DebugLinkDebugInfo)) {
			return false;
		}
		DebugLinkDebugInfo other = (DebugLinkDebugInfo) obj;
		return crc == other.crc && Objects.equals(filename, other.filename);
	}

	@Override
	public String toString() {
		return String.format("DebugLinkDebugInfo [filename=%s, crc=%s]", filename, crc);
	}

}
