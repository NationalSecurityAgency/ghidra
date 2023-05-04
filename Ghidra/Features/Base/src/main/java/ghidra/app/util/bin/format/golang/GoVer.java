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

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

/**
 * Golang version numbers
 */
public enum GoVer {
	UNKNOWN(0, 0),
	V1_2(1, 2),
	V1_16(1, 16),
	V1_17(1, 17),
	V1_18(1, 18);

	private final int major;
	private final int minor;

	private GoVer(int major, int minor) {
		this.major = major;
		this.minor = minor;
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

	/**
	 * Compares this version to the specified other version and returns true if this version
	 * is greater than or equal to the other version.
	 * 
	 * @param otherVersion version info to compare
	 * @return true if this version is gte other version
	 */
	public boolean isAtLeast(GoVer otherVersion) {
		return this.ordinal() >= otherVersion.ordinal();
	}

	/**
	 * Parses a version string ("1.2") and returns the matching GoVer enum instance, or
	 * UNKNOWN if no matching version or bad data.
	 *  
	 * @param s string to parse
	 * @return GoVer enum instance, or UNKNOWN
	 */
	public static GoVer parse(String s) {
		String[] parts = s.split("\\.");
		if (parts.length < 2) {
			return UNKNOWN;
		}
		try {
			int major = Integer.parseInt(parts[0]);
			int minor = Integer.parseInt(parts[1]);
			for (GoVer ver : values()) {
				if (ver.major == major && ver.minor == minor) {
					return ver;
				}
			}
		}
		catch (NumberFormatException e) {
			return UNKNOWN;
		}
		return UNKNOWN;
	}

	public static final String GOLANG_VERSION_PROPERTY_NAME = "Golang go version";
	public static GoVer fromProgramProperties(Program program) {
		Options props = program.getOptions(Program.PROGRAM_INFO);
		String verStr = props.getString(GOLANG_VERSION_PROPERTY_NAME, null);
		return verStr != null ? parse(verStr) : UNKNOWN;
	}

	public static void setProgramPropertiesWithOriginalVersionString(Options props, String s) {
		props.setString(GOLANG_VERSION_PROPERTY_NAME, s);
	}

}
