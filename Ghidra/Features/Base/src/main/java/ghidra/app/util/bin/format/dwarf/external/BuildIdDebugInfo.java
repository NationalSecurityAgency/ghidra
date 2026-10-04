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

import java.util.*;

import ghidra.app.util.bin.format.elf.info.NoteGnuBuildId;
import ghidra.program.model.listing.Program;

/**
 * Represents {@link ExternalDebugInfo} found in a build-id property embedded in an ELF file.
 */
public class BuildIdDebugInfo implements ExternalDebugInfo {
	private static final int MIN_BUILDID_HASH_LENGTH = 20;

	public static BuildIdDebugInfo fromProgram(Program program) {
		NoteGnuBuildId buildId = NoteGnuBuildId.fromProgram(program);
		return buildId != null && buildId.getDescription().length >= MIN_BUILDID_HASH_LENGTH
				? new BuildIdDebugInfo(buildId.getDescription())
				: null;
	}

	private final byte[] buildId;
	private final ObjectType objectType;
	private final String extra;

	/**
	 * Creates a new {@link BuildIdDebugInfo} from the bytes of its hash digest
	 * 
	 * @param buildId bytes of the hash digest
	 */
	public BuildIdDebugInfo(byte[] buildId) {
		this(buildId, ObjectType.DEBUGINFO, null);
	}

	/**
	 * Creates a new {@link BuildIdDebugInfo} from the bytes of its hash digest, a specifier for the
	 * type of the object being pointed to, and an optional path used ObjectType.SOURCE instances.
	 * 
	 * @param buildId build-id hash digest found in ".note.gnu.build-id" section
	 * @param objectType {@link ObjectType} specifies what kind of debug file is specified by the
	 * other info  
	 * @param extra additional information used by {@link ObjectType#SOURCE} 
	 */
	public BuildIdDebugInfo(byte[] buildId, ObjectType objectType, String extra) {
		Objects.requireNonNull(buildId);

		this.buildId = buildId;
		this.objectType = objectType;
		this.extra = extra;
	}

	/**
	 * Return the build-id.
	 * 
	 * @return build-id hash string
	 */
	public String getBuildIdHexString() {
		return HexFormat.of().formatHex(buildId);
	}

	/**
	 * {@return ObjectType that this build-id specifier points to}
	 */
	public ObjectType getObjectType() {
		return objectType;
	}

	/**
	 * {@return extra info used by ObjectTypes that need it}
	 */
	public String getExtra() {
		return extra;
	}

	/**
	 * {@return a new BuildIdDebugInfo instance, pointing to the same build-id hash but an
	 * alternate object associated with the base debug file}
	 * @param newObjectType the new {@link ObjectType}
	 * @param newExtra extra information used by the ObjectType to find the target file
	 */
	public BuildIdDebugInfo withType(ObjectType newObjectType, String newExtra) {
		return new BuildIdDebugInfo(buildId, newObjectType, newExtra);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(buildId);
		result = prime * result + Objects.hash(extra, objectType);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof BuildIdDebugInfo)) {
			return false;
		}
		BuildIdDebugInfo other = (BuildIdDebugInfo) obj;
		return Arrays.equals(buildId, other.buildId) && Objects.equals(extra, other.extra) &&
			objectType == other.objectType;
	}

	@Override
	public String toString() {
		return "BuildIdDebugInfo [" +
			(buildId != null ? "buildId=" + Arrays.toString(buildId) + ", " : "") +
			(objectType != null ? "objectType=" + objectType + ", " : "") +
			(extra != null ? "extra=" + extra : "") + "]";
	}

}
