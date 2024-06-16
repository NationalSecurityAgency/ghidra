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
import java.util.*;

/**
 * Represents information about a single golang module dependency.
 * 
 * @param path module path 
 * @param version module version
 * @param sum checksum
 * @param replace replacement module info  (may be null)
 */
public record GoModuleInfo(String path, String version, String sum, GoModuleInfo replace) {

	/**
	 * Parses a GoModuleInfo from a formatted string "path[tab]version[tab]checksum".
	 * 
	 * @param s string to parse
	 * @param replace GoModuleInfo that is the replacement for this module, or null if no 
	 * replacement specified
	 * @return new GoModuleInfo instance, never null
	 * @throws IOException if error parsing string
	 */
	public static GoModuleInfo fromString(String s, GoModuleInfo replace) throws IOException {
		String[] parts = s.split("\t");
		if (parts.length != 2 && parts.length != 3) {
			throw new IOException();
		}
		return new GoModuleInfo(parts[0], parts[1], parts.length == 3 ? parts[2] : null, replace);
	}

	/**
	 * Returns a formatted version of the information in this instance.
	 * 
	 * @return formatted string
	 */
	public String getFormattedString() {
		return replace == null
				? "%s %s %s".formatted(path, version, sum != null ? sum : "")
				: "%s %s => %s".formatted(path, version, replace.getFormattedString());
	}

	/**
	 * Returns the values in this object as elements of a map.
	 * 
	 * @param prefix String prefix to put in front of each value name
	 * @return map of String &rarr; String
	 */
	public Map<String, String> asKeyValuePairs(String prefix) {
		Map<String, String> result = new HashMap<>();
		result.put(prefix + "path", Objects.requireNonNullElse(path, "-missing-"));
		result.put(prefix + "version", Objects.requireNonNullElse(version, "-missing-"));
		if (sum != null) {
			result.put(prefix + "sum", sum);
		}
		if (replace != null) {
			result.put(prefix + "replace", replace.getFormattedString());
		}
		return result;
	}

}
