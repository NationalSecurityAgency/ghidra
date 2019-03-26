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
package ghidra.app.util.opinion;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.util.exception.AssertException;

/**
 * An object to parse a line from a ".def" file.
 */
class DefExportLine {

	private Pattern EXPORT_LINE_PATTERN = Pattern.compile("\\s*(\\w+)(\\s@\\d+)?(\\s\\w+)?");

	private String name;
	private int ordinal;
	private String type;

	DefExportLine(String exportLine) {

		//
		// Format: FunctionName [@1] [PRIVATE]
		//

		Matcher matcher = EXPORT_LINE_PATTERN.matcher(exportLine);
		if (!matcher.matches()) {
			throw new AssertException("Unexpected '.def' file line format.  " +
				"Expected 'Name [@number] [PRIVATE]';" + " found " + exportLine);
		}

		name = matcher.group(1);
		String ordinalString = matcher.group(2);
		if (ordinalString != null) { // this is optional				
			ordinalString = ordinalString.trim().substring(1); // strip off '@'
			ordinal = Integer.parseInt(ordinalString);
		}

		String privateString = matcher.group(3);
		if (privateString != null) {
			type = privateString.trim();
		}
	}

	int getOrdinal() {
		return ordinal;
	}

	String getName() {
		return name;
	}

	String getType() {
		return type;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" + 
			"\tname: " + name + ",\n" + 
			"\tordinal: "  + ordinal + ",\n" + 
			"\ttype: " + type + "\n" +
		"}";
		//@formatter:on
	}
}
