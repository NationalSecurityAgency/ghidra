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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a range of versions
 * 
 * @param start first version contained in the range 
 * @param end last version contained in the range
 */
public record GoVerRange(GoVer start, GoVer end) {
	public static final GoVerRange ALL = new GoVerRange(GoVer.ANY, GoVer.ANY);
	public static final GoVerRange EMPTY = new GoVerRange(GoVer.INVALID, GoVer.INVALID);

	/**
	 * Parses a version range string (eg. "1.2-1.5", or "-1.5", or "1.2+")
	 * <p>
	 * Version ranges can be specified with leading or trailing wildcards
	 * (eg. "-end_ver", or "start_ver-", or "start_ver+").
	 * 
	 * @param s string to parse
	 * @return returns a {@link GoVerRange} instance, or the special {@link #EMPTY} instance
	 * if the string string is bad
	 */
	public static GoVerRange parse(String s) {
		String[] verNums = s.split("[+-]", -1); // "1.2-1.5" or "1.2+" or "-1.2"
		String startStr = verNums[0];
		String endStr = verNums.length > 1 ? verNums[1] : verNums[0];

		GoVer start = startStr.isBlank() ? GoVer.ANY : GoVer.parseWildcardPatch(startStr);
		GoVer end = (endStr == startStr)
				? start
				: endStr.isBlank()
						? GoVer.ANY
						: GoVer.parseWildcardPatch(endStr);

		return (start == GoVer.ANY && end == GoVer.ANY) || (start.isInvalid() || end.isInvalid())
				? EMPTY
				: new GoVerRange(start, end);
	}

	/**
	 * Returns true if this range is empty
	 * 
	 * @return boolean true if empty
	 */
	public boolean isEmpty() {
		return start.isInvalid() || end.isInvalid();
	}
	
	/**
	 * Returns true if this range has wildcard start or end
	 * 
	 * @return boolean true if has wildcard boundaries
	 */
	public boolean hasWildcard() {
		return start.isWildcard() || end.isWildcard();
	}

	/**
	 * Returns true if this range contains the specified version.
	 * 
	 * @param ver {@link GoVer} to test
	 * @return boolean true if present, false if not
	 */
	public boolean contains(GoVer ver) {
		return (!start.isInvalid() && !end.isInvalid()) &&
			(start.isWildcard() || start.compareTo(ver) <= 0) &&
			(end.isWildcard() || end.compareTo(ver) >= 0);
	}
	
	/**
	 * Returns a list of minor GoVers between the start and end of this range (inclusive).
	 * <p>
	 * NOTE: does not work if the major version is different between start and end.
	 * 
	 * @return List of GoVers
	 * @throws IOException if start and end are not same major ver
	 */
	public List<GoVer> asList() throws IOException {
		if ( start.major()  != end.major() || isEmpty() || hasWildcard() ) {
			throw new IOException("Unable to make version list, invalid or wildcard or spans versions");
		}
		List<GoVer> result = new ArrayList<>();
		GoVer current = start;
		for(int minor = current.getMinor(); minor <= end.minor(); minor++) {
			result.add(new GoVer(1, minor, 0));
		}
		return result;
		
	}
}
