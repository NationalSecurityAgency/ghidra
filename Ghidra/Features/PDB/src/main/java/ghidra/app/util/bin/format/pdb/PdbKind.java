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
package ghidra.app.util.bin.format.pdb;

public enum PdbKind {

	//@formatter:off
	STRUCTURE, 
	UNION, 
	MEMBER, 
	STATIC_LOCAL, 
	OBJECT_POINTER, 
	PARAMETER, 
	LOCAL, 
	UNKNOWN;
	//@formatter:on

	private final String camelName;

	private PdbKind() {
		camelName = toCamel(name());
	}

	/**
	 * Get the name in camel form
	 * @return name in camel form
	 */
	public String getCamelName() {
		return camelName;
	}

	private static String toCamel(String name) {
		StringBuilder buf = new StringBuilder();
		boolean makeUpper = true;
		for (char c : name.toCharArray()) {
			if (c == '_') {
				makeUpper = true;
				continue;
			}
			if (makeUpper) {
				c = Character.toUpperCase(c);
			}
			buf.append(c);
		}
		return buf.toString();
	}

	/**
	 * Parse case-insensitive kind string and return corresponding PdbKind.
	 * It is expected that kind strings will be camel notation (e.g., OBJECT_POINTER 
	 * kind string would be ObjectPointer).
	 * If not identified UNKNOWN will be returned.
	 * @param kind kind string (underscores not permitted)
	 * @return PdbKind
	 */
	public static PdbKind parse(String kind) {
		for (PdbKind pdbKind : values()) {
			if (pdbKind.camelName.equalsIgnoreCase(kind)) {
				return pdbKind;
			}
		}
		return UNKNOWN;
	}

}
