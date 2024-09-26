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
package ghidra.app.util.bin.format.golang;

import java.util.Objects;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

/**
 * Golang version numbers
 */
public class GoVer implements Comparable<GoVer> {
	public static final GoVer INVALID = new GoVer(0, 0);
	public static final GoVer ANY = new GoVer(-1, -1);

	// a couple of well-known versions that are re-used in a few places
	public static final GoVer V1_2 = new GoVer(1, 2);
	public static final GoVer V1_16 = new GoVer(1, 16);
	public static final GoVer V1_17 = new GoVer(1, 17);
	public static final GoVer V1_18 = new GoVer(1, 18);

	private final int major;
	private final int minor;

	public GoVer(int major, int minor) {
		this.major = major;
		this.minor = minor;
	}

	public boolean isInvalid() {
		return major == 0 && minor == 0;
	}

	public boolean isWildcard() {
		return major == -1 && minor == -1;
	}

	/**
	 * Major value
	 * 
	 * @return major
	 */
	public int getMajor() {
		return major;
	}

	/**
	 * Minor value
	 * 
	 * @return minor
	 */
	public int getMinor() {
		return minor;
	}

	@Override
	public int compareTo(GoVer o) {
		int result = Integer.compare(major, o.major);
		if (result == 0) {
			result = Integer.compare(minor, o.minor);
		}
		return result;
	}

	/**
	 * Compares this version to the specified other version and returns true if this version
	 * is greater than or equal to the other version.
	 * 
	 * @param otherVersion version info to compare
	 * @return true if this version is gte other version
	 */
	public boolean isAtLeast(GoVer otherVersion) {
		return compareTo(otherVersion) >= 0;
	}

	/**
	 * Returns true if this version is between the specified min and max versions (inclusive).
	 * 
	 * @param min minimum version to allow (inclusive)
	 * @param max maximum version to allow (inclusive)
	 * @return boolean true if this version is between the specified min and max versions
	 */
	public boolean inRange(GoVer min, GoVer max) {
		return min.compareTo(this) <= 0 && this.compareTo(max) <= 0;
	}

	/**
	 * Parses a version string ("1.2") and returns a GoVer instance, or
	 * INVALID if no matching version or bad data.
	 *  
	 * @param s string to parse
	 * @return GoVer instance, or INVALID
	 */
	public static GoVer parse(String s) {
		String[] parts = Objects.requireNonNullElse(s, "").split("\\.");
		if (parts.length < 2) {
			return INVALID;
		}
		try {
			int major = Integer.parseInt(parts[0]);
			int minor = Integer.parseInt(parts[1]);
			//don't care about patch level right now
			return new GoVer(major, minor);
		}
		catch (NumberFormatException e) {
			// fall thru, return unknown
		}
		return INVALID;
	}

	public static final String GOLANG_VERSION_PROPERTY_NAME = "Golang go version";
	public static GoVer fromProgramProperties(Program program) {
		Options props = program.getOptions(Program.PROGRAM_INFO);
		String verStr = props.getString(GOLANG_VERSION_PROPERTY_NAME, null);
		return parse(verStr);
	}

	public static void setProgramPropertiesWithOriginalVersionString(Options props, String s) {
		props.setString(GOLANG_VERSION_PROPERTY_NAME, s);
	}

	@Override
	public int hashCode() {
		return Objects.hash(major, minor);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof GoVer)) {
			return false;
		}
		GoVer other = (GoVer) obj;
		return major == other.major && minor == other.minor;
	}

	@Override
	public String toString() {
		return "%d.%d".formatted(major, minor);
	}

}
