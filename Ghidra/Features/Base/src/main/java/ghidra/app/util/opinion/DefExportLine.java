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

import java.io.IOException;
import java.util.StringTokenizer;

/**
 * An object to parse an EXPORTS line from a ".def" file.
 * 
 * @see <a href="https://learn.microsoft.com/en-us/cpp/build/reference/exports?view=msvc-170">EXPORTS</a> 
 * 
 */
class DefExportLine {

	private String name;
	private String internalName;
	private String otherModuleName;
	private String otherModuleExportedName;
	private Integer otherModuleOrdinal;
	private Integer ordinal;
	private boolean isNoName;
	private boolean isPrivate;
	private boolean isData;

	/**
	 * Parses the given export line into a new {@link DefExportLine}
	 * 
	 * @param exportLine The export line
	 * @throws IOException if there was a problem parsing
	 */
	DefExportLine(String exportLine) throws IOException {
		StringTokenizer st = new StringTokenizer(exportLine);
		if (!st.hasMoreTokens()) {
			throw new IOException("Line is empty");
		}
		while (st.hasMoreTokens()) {
			String token = st.nextToken();
			if (name == null) {
				String[] equalsParts = token.split("=", 2);
				name = equalsParts[0];
				if (equalsParts.length > 1) {
					String[] dotParts = equalsParts[1].split("\\.", 2);
					if (dotParts.length == 1) {
						internalName = equalsParts[1];
					}
					else {
						otherModuleName = dotParts[0];
						if (dotParts[1].startsWith("#")) {
							otherModuleOrdinal = parseInt(dotParts[1].substring(1));
						}
						else {
							otherModuleExportedName = dotParts[1];
						}
					}
				}
			}
			else if (ordinal == null && token.startsWith("@")) {
				if (!token.equals("@")) {
					ordinal = parseInt(token.substring(1));
				}
				else if (st.hasMoreTokens()) {
					ordinal = parseInt(st.nextToken());
				}
			}
			else {
				switch (token) {
					case "NONAME":
						isNoName = true;
						break;
					case "PRIVATE":
						isPrivate = true;
						break;
					case "DATA":
						isData = true;
						break;
					default:
						throw new IOException("Invalid type: " + token);
				}
			}
		}

	}

	/**
	 * {@return the name}
	 */
	String getName() {
		return name;
	}

	/**
	 * {@return the internal name, or null if there is no internal name}
	 */
	String getInternalName() {
		return internalName;
	}

	/**
	 * {@return the other module name, or null if there is no other module}
	 */
	String getOtherModuleName() {
		return otherModuleName;
	}

	/**
	 * {@return the other module exported name, or null if there is no other module exported name}
	 */
	String getOtherModuleExportedName() {
		return otherModuleExportedName;
	}

	/**
	 * {@return the other module ordinal, or null if there is no other module ordinal}
	 */
	Integer getOtherModuleOrdinal() {
		return otherModuleOrdinal;
	}

	/**
	 * {@return the ordinal value, or null if there is no ordinal}
	 */
	Integer getOrdinal() {
		return ordinal;
	}

	/**
	 * {@return true if the export has no name; otherwise, false}
	 */
	boolean isNoName() {
		return isNoName;
	}

	/**
	 * {@return true if the export is private; otherwise, false}
	 */
	boolean isPrivate() {
		return isPrivate;
	}

	/**
	 * {@return true if the export is data; otherwise, false}
	 */
	boolean isData() {
		return isData;
	}

	/**
	 * Parses the {@link String} argument as a signed decimal integer
	 * 
	 * @param str The {@link String} to parse
	 * @return The integer value represented by the argument in decimal
	 * @throws IOException if the {@link String} does not contain a parseable integer
	 */
	private int parseInt(String str) throws IOException {
		try {
			return Integer.parseInt(str);
		}
		catch (NumberFormatException e) {
			throw new IOException(e);
		}
	}
}
