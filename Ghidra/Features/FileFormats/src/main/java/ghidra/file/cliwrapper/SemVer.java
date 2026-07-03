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
package ghidra.file.cliwrapper;

import java.util.Objects;

/**
 * Record that represents a semantic version number. (eg. X.Y.Z)
 * 
 * @param major major version number
 * @param minor minor version number
 * @param patch patch version number
 */
public record SemVer(int major, int minor, int patch) implements Comparable<SemVer> {

	public static final SemVer INVALID = new SemVer(0, 0, 0);
	public static final SemVer ANY = new SemVer(-1, -1, -1);

	/**
	 * Parses a version string ("1.2.0") and returns a SemVer instance, or INVALID if bad data.
	 * <p>
	 * Missing patch numbers will be defaulted to 0.
	 *  
	 * @param s string to parse, "1.2.3", or "1.2"
	 * @return SemVer instance, or INVALID
	 */
	public static SemVer parse(String s) {
		return parse(s, 0);
	}

	/**
	 * Parses a version string ("1.2.0") and returns a SemVer instance, or INVALID if bad data.
	 * <p>
	 * Missing patch numbers will be replaced with the wildcard value.
	 *  
	 * @param s string to parse, "1.2.3", or "1.2"
	 * @return SemVer instance, or INVALID
	 */
	public static SemVer parseWildcardPatch(String s) {
		return parse(s, -1);
	}

	private static SemVer parse(String s, int missingPatchValue) {
		// handle extra info at end of ver string: "1.22.8 blah"
		String[] parts =
			Objects.requireNonNullElse(s, "").replaceAll("[^.0-9].*$", "").split("\\.");
		if (parts.length < 2) {
			return INVALID;
		}
		try {
			int major = Integer.parseInt(parts[0]);
			int minor = Integer.parseInt(parts[1]);
			int patch = parts.length > 2 ? Integer.parseInt(parts[2]) : missingPatchValue;
			return new SemVer(major, minor, patch);
		}
		catch (NumberFormatException e) {
			// fall thru, return invalid
		}
		return INVALID;
	}

	public boolean isInvalid() {
		return major == 0 && minor == 0;
	}

	public boolean isWildcard() {
		return major == -1 && minor == -1;
	}

	/**
	 * {@return major value}
	 */
	public int getMajor() {
		return major;
	}

	/**
	 * {@return minor value}
	 */
	public int getMinor() {
		return minor;
	}

	/**
	 * {@return patch value}
	 */
	public int getPatch() {
		return patch;
	}

	public SemVer prevPatch() {
		return new SemVer(major, minor, patch > 0 ? patch - 1 : 0);
	}

	public SemVer withPatch(int newPatchNum) {
		return new SemVer(major, minor, newPatchNum);
	}

	@Override
	public int compareTo(SemVer o) {
		int result = Integer.compare(major, o.major);
		if (result == 0) {
			result = Integer.compare(minor, o.minor);
		}
		if (result == 0) {
			result = patch == -1 || o.patch == -1 ? 0 : Integer.compare(patch, o.patch);
		}
		return result;
	}

	@Override
	public String toString() {
		return patch != -1
				? "%d.%d.%d".formatted(major, minor, patch)
				: "%d.%d".formatted(major, minor);
	}
}
