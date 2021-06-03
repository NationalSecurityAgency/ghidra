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
package ghidra.framework;

/**
 * Class to represent an application's version information.
 * <p>
 * The version format is \d\.\d(\.\d)?(\-.+)?
 * <p>
 * Note: this class has a natural ordering that is inconsistent with equals (the <code>tag</code>
 * part of the version is disregarded in the {@link #compareTo(ApplicationVersion)} method).
 * <p>
 * Examples:
 * <ul>
 * <li>7.4
 * <li>7.4.1
 * <li>7.4.1-BETA
 * </ul>
 */
public class ApplicationVersion implements Comparable<ApplicationVersion> {

	private int major;
	private int minor;
	private int patch;
	private String tag;

	/**
	 * Creates a new {@link ApplicationVersion} object from the given version string.
	 * 
	 * @param version A version string.
	 * @throws IllegalArgumentException if the version string failed to parse.  The 
	 *   exception's message has more detailed information about why it failed.
	 */
	public ApplicationVersion(String version) throws IllegalArgumentException {
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

	/**
	 * Gets the tag.
	 * 
	 * @return The tag.  Could be the empty string.
	 */
	public String getTag() {
		return tag;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(major);
		builder.append(".");
		builder.append(minor);
		if (patch > 0) {
			builder.append(".");
			builder.append(patch);
		}
		if (!tag.isEmpty()) {
			builder.append("-");
			builder.append(tag);
		}
		return builder.toString();
	}

	@Override
	public int compareTo(ApplicationVersion other) {
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
		result += tag.hashCode();
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
		ApplicationVersion other = (ApplicationVersion) obj;
		if (major != other.major) {
			return false;
		}
		if (minor != other.minor) {
			return false;
		}
		if (patch != other.patch) {
			return false;
		}
		if (!tag.equals(other.tag)) {
			return false;
		}
		return true;
	}

	/**
	 * Parses the major, minor, patch, and tag components out of the given version string.
	 * 
	 * @param version A version string.
	 * @throws IllegalArgumentException if the version string failed to parse.  The 
	 *   exception's message has more detailed information about why it failed.
	 */
	private void parse(String version) throws IllegalArgumentException {
		if (version == null) {
			throw new IllegalArgumentException("Version is null");
		}

		tag = "";
		int dashIndex = version.indexOf('-');
		if (dashIndex != -1) {
			if (dashIndex + 1 < version.length()) {
				tag = version.substring(dashIndex + 1);
			}
			version = version.substring(0, dashIndex);
		}

		String[] versionParts = version.split("\\.");
		if (versionParts.length == 2) {
			major = parse(versionParts[0], "major");
			minor = parse(versionParts[1], "minor");
			patch = 0;
		}
		else if (versionParts.length == 3) {
			major = parse(versionParts[0], "major");
			minor = parse(versionParts[1], "minor");
			patch = parse(versionParts[2], "patch");
		}
		else {
			String plural = version.length() > 1 ? "s" : "";
			throw new IllegalArgumentException(
				"Version '" + version + "' has " + versionParts.length +
					" part" + plural + " but 2 or 3 are required");
		}
	}

	/**
	 * Parses a version part string to an integer.
	 * 
	 * @param versionPart A version part string.
	 * @param versionPartName The version part name (for error reporting).
	 * @return The version part string as an integer.
	 * @throws IllegalArgumentException if the version part string failed to parse to a valid
	 *   version part integer.
	 */
	private int parse(String versionPart, String versionPartName) throws IllegalArgumentException {
		try {
			int i = Integer.parseInt(versionPart);
			if (i < 0) {
				throw new IllegalArgumentException(versionPartName + " cannot be negative");
			}
			return i;
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException(
				"Failed to convert " + versionPartName + " version to integer");
		}
	}
}
