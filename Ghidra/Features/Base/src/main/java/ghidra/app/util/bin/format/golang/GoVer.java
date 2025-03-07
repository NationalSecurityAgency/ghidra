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
 * Represents a Golang version number (major.minor.patch), with some special sentinel values
 * for wildcarding.
 * 
 * @param major currently just 1
 * @param minor second part of version number, ranges from 0..unknown upper limit
 * @param patch third part of version number, ranges from 0..unknown upper limit per minor version
 */
public record GoVer(int major, int minor, int patch) implements Comparable<GoVer> {

	public static final String GOLANG_VERSION_PROPERTY_NAME = "Golang go version";

	public static final GoVer INVALID = new GoVer(0, 0, 0);
	public static final GoVer ANY = new GoVer(-1, -1, -1);

	/**
	 * Parses a version string ("1.2.0") and returns a GoVer instance, or INVALID if bad data.
	 * <p>
	 * Missing patch numbers will be defaulted to 0.
	 *  
	 * @param s string to parse, "1.2.3", or "1.2"
	 * @return GoVer instance, or INVALID
	 */
	public static GoVer parse(String s) {
		return parse(s, 0);
	}
	
	/**
	 * Parses a version string ("1.2.0") and returns a GoVer instance, or INVALID if bad data.
	 * <p>
	 * Missing patch numbers will be replaced with the wildcard value.
	 *  
	 * @param s string to parse, "1.2.3", or "1.2"
	 * @return GoVer instance, or INVALID
	 */
	public static GoVer parseWildcardPatch(String s) {
		return parse(s, -1);
	}
	
	private static GoVer parse(String s, int missingPatchValue) {
		// handle extra info at end of ver string: "1.22.8 X:rangefunc"
		String[] parts =
			Objects.requireNonNullElse(s, "").replaceAll("[^.0-9].*$", "").split("\\.");
		if (parts.length < 2) {
			return INVALID;
		}
		try {
			int major = Integer.parseInt(parts[0]);
			int minor = Integer.parseInt(parts[1]);
			int patch = parts.length > 2
					? Integer.parseInt(parts[2])
					: missingPatchValue;
			return new GoVer(major, minor, patch);
		}
		catch (NumberFormatException e) {
			// fall thru, return invalid
		}
		return INVALID;
	}

	/**
	 * Parses a version string found in a Ghidra program info properties list
	 * 
	 * @param program {@link Program}
	 * @return {@link GoVer} instance, or INVALID, never null
	 */
	public static GoVer fromProgramProperties(Program program) {
		Options props = program.getOptions(Program.PROGRAM_INFO);
		String verStr = props.getString(GOLANG_VERSION_PROPERTY_NAME, null);
		return parse(verStr, 0);
	}

	/**
	 * Writes a version string to a Ghidra program info properties list.
	 * 
	 * @param props props from a program
	 * @param s version string
	 */
	public static void setProgramPropertiesWithOriginalVersionString(Options props, String s) {
		props.setString(GOLANG_VERSION_PROPERTY_NAME, s);
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

	/**
	 * Patch value
	 * 
	 * @return patch
	 */
	public int getPatch() {
		return patch;
	}

	public GoVer prevPatch() {
		return new GoVer(major, minor, patch > 0 ? patch - 1 : 0);
	}

	public GoVer withPatch(int newPatchNum) {
		return new GoVer(major, minor, newPatchNum);
	}

	@Override
	public int compareTo(GoVer o) {
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
