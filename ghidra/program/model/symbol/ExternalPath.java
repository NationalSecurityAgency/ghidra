/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.symbol;

public class ExternalPath {

	private static final String DELIMITER_STRING = "::";
	private String[] strings;

	public ExternalPath(String... strings) {
		for (String string : strings) {
			if (string == null || string.length() <= 0) {
				throw new IllegalArgumentException(
					"An external path cannot contain a null or empty string.");
			}
		}
		if (strings.length < 2) {
			throw new IllegalArgumentException(
				"An external path must specify a library name and a label.");
		}
		this.strings = strings;
	}

	public String getLibraryName() {
		return strings[0];
	}

	public String getName() {
		return strings[strings.length - 1];
	}

	public String[] getPathElements() {
		// FIXME Make the array that is returned immutable instead.
		String[] path = new String[strings.length];
		System.arraycopy(strings, 0, path, 0, strings.length);
		return path;
	}

	@Override
	public String toString() {
		int lastIndex = strings.length - 1;
		StringBuffer buffer = new StringBuffer();
		for (int i = 0; i < strings.length; i++) {
			buffer.append(strings[i]);
			if (i < lastIndex) {
				buffer.append(DELIMITER_STRING);
			}
		}
		return buffer.toString();
	}
}
