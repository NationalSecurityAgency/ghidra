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
package ghidra.launch;

import java.text.ParseException;

/**
 * Class to more conveniently represent a Java version string.
 */
public class JavaVersion implements Comparable<JavaVersion> {

	private int major;
	private int minor;
	private int patch;

	/**
	 * Creates a new {@link JavaVersion} object from the given version string.
	 * 
	 * @param version A version string.
	 * @throws ParseException if the version string failed to parse.  The exception's 
	 *   message has more detailed information about why it failed.
	 */
	public JavaVersion(String version) throws ParseException {
		parse(version);
	}

	/**
	 * Gets the major version.
	 * 
	 * @return The major version.
	 */
	public int getMajor() {
		return major;
	}

	/**
	 * Gets the minor version.
	 * 
	 * @return The minor version.
	 */
	public int getMinor() {
		return minor;
	}

	/**
	 * Gets the patch version.
	 * 
	 * @return The patch version.
	 */
	public int getPatch() {
		return patch;
	}

	@Override
	public String toString() {
		if (major < 9) {
			return String.format("1.%d.%d_%d", major, minor, patch);
		}
		return String.format("%d.%d.%d", major, minor, patch);
	}

	@Override
	public int compareTo(JavaVersion other) {
		if (major > other.major) {
			return 1;
		}
		if (major < other.major) {
			return -1;
		}
		if (minor > other.minor) {
			return 1;
		}
		if (minor < other.minor) {
			return -1;
		}
		if (patch > other.patch) {
			return 1;
		}
		if (patch < other.patch) {
			return -1;
		}
		return 0;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + major;
		result = prime * result + minor;
		result = prime * result + patch;
		return result;
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
		JavaVersion other = (JavaVersion) obj;
		if (major != other.major) {
			return false;
		}
		if (minor != other.minor) {
			return false;
		}
		if (patch != other.patch) {
			return false;
		}
		return true;
	}

	/**
	 * Parses the major, minor, and optional patch integers out of the given version string.
	 * 
	 * @param version A version string.
	 * @throws ParseException if the version string failed to parse.  The exception's message 
	 * has more detailed information about why it failed.
	 */
	private void parse(String version) throws ParseException {
		if (version == null) {
			throw new ParseException("Version is null", 0);
		}

		major = minor = patch = 0;

		// Remove any surrounding double quotes
		if (version.startsWith("\"") && version.endsWith("\"")) {
			version = version.substring(1, version.length() - 1);
		}

		// Remove any trailing dash section (9-Ubuntu is a thing).
		int dashIndex = version.indexOf('-');
		if (dashIndex > 0) {
			version = version.substring(0, dashIndex);
		}

		String[] versionParts = version.split("[._]");
		int firstValue = parse(versionParts[0], "first value");
		if (firstValue == 1) {
			// Follows the Java 8 and earlier format of 1.major.minor_patch
			if (versionParts.length > 1) {
				major = parse(versionParts[1], "major");
				if (versionParts.length > 2) {
					minor = parse(versionParts[2], "minor");
					if (versionParts.length > 3) {
						patch = parse(versionParts[3], "patch");
					}
				}
			}
		}
		else if (firstValue >= 9) {
			// Follows the Java 9 and later format of major.minor.patch
			major = parse(versionParts[0], "major");
			if (versionParts.length > 1) {
				minor = parse(versionParts[1], "minor");
				if (versionParts.length > 2) {
					patch = parse(versionParts[2], "patch");
				}
			}
		}
		else {
			throw new ParseException("Failed to parse version: " + version, 0);
		}
	}

	/**
	 * Parses a version part string to an integer.
	 * 
	 * @param versionPart A version part string.
	 * @param versionPartName The version part name (for error reporting).
	 * @return The version part string as an integer.
	 * @throws ParseException if the version part string failed to parse to a valid version part 
	 *   integer.
	 */
	private int parse(String versionPart, String versionPartName) throws ParseException {
		try {
			int i = Integer.parseInt(versionPart);
			if (i < 0) {
				throw new ParseException(versionPartName + " cannot be negative", 0);
			}
			return i;
		}
		catch (NumberFormatException e) {
			throw new ParseException("Failed to convert " + versionPartName + " version to integer",
				0);
		}
	}
}
