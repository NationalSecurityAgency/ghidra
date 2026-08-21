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

import ghidra.app.util.bin.format.elf.info.GnuDebugLink;
import ghidra.app.util.bin.format.elf.info.NoteGnuBuildId;
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
		GnuDebugLink debugLink = GnuDebugLink.fromProgram(program);
		NoteGnuBuildId buildId = NoteGnuBuildId.fromProgram(program);
		if (debugLink == null && buildId == null) {
			return null;
		}

		String filename = debugLink != null ? debugLink.getFilename() : null;
		int crc = debugLink != null ? debugLink.getCrc() : 0;
		String hash = buildId != null
				? NumericUtilities.convertBytesToString(buildId.getDescription())
				: null;

		return new ExternalDebugInfo(filename, crc, hash, ObjectType.DEBUGINFO, null);
	}

	/**
	 * {@return a new ExternalDebugInfo instance created using the specified Build-Id value}
	 * @param buildId hex string
	 */
	public static ExternalDebugInfo forBuildId(String buildId) {
		return new ExternalDebugInfo(null, 0, buildId, ObjectType.DEBUGINFO, null);
	}

	/**
	 * {@return a new ExternalDebugInfo instance created using the specified debuglink values}
	 * @param debugLinkFilename filename from debuglink section
	 * @param crc crc32 from debuglink section
	 */
	public static ExternalDebugInfo forDebugLink(String debugLinkFilename, int crc) {
		return new ExternalDebugInfo(debugLinkFilename, crc, null, ObjectType.DEBUGINFO, null);
	}

	private final String filename;
	private final int crc;
	private final String buildId;
	private final ObjectType objectType;
	private final String extra;

	/**
	 * Constructor to create an {@link ExternalDebugInfo} instance.
	 * 
	 * @param filename filename of external debug file, or null
	 * @param crc crc32 of external debug file, or 0 if no filename 
	 * @param buildId build-id hash digest found in ".note.gnu.build-id" section, or null if
	 * not present 
	 * @param objectType {@link ObjectType} specifies what kind of debug file is specified by the
	 * other info  
	 * @param extra additional information used by {@link ObjectType#SOURCE} 
	 */
	public ExternalDebugInfo(String filename, int crc, String buildId, ObjectType objectType,
			String extra) {
		this.filename = filename;
		this.crc = crc;
		this.buildId = buildId;
		this.objectType = objectType;
		this.extra = extra;
	}

	/**
	 * Return true if there is a filename
	 * 
	 * @return boolean true if filename is available, false if not
	 */
	public boolean hasDebugLink() {
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
	 * Return the build-id.
	 * 
	 * @return build-id hash string
	 */
	public String getBuildId() {
		return buildId;
	}

	/**
	 * {@return true if buildId is available, false if not}
	 */
	public boolean hasBuildId() {
		return buildId != null && !buildId.isBlank();
	}

	public ObjectType getObjectType() {
		return objectType;
	}

	public String getExtra() {
		return extra;
	}

	public ExternalDebugInfo withType(ObjectType newObjectType, String newExtra) {
		return new ExternalDebugInfo(extra, crc, buildId, newObjectType, newExtra);
	}

	@Override
	public String toString() {
		return String.format(
			"ExternalDebugInfo [filename=%s, crc=%s, hash=%s, objectType=%s, extra=%s]", filename,
			crc, buildId, objectType, extra);
	}

}
