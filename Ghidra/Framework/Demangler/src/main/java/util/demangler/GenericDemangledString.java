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
package util.demangler;

public class GenericDemangledString extends GenericDemangledObject {
	private String string;
	private int length;
	private boolean unicode;

	public GenericDemangledString(String string, int length, boolean unicode) {
		this.string = string;
		this.length = length;
		this.unicode = unicode;
	}

	@Override
	public String getSignature(boolean format) {
		StringBuffer buffer = new StringBuffer();
		if (specialPrefix != null) {
			buffer.append(specialPrefix + " for ");
		}
		buffer.append(string);
		if (specialSuffix != null) {
			buffer.append(" " + specialSuffix);
		}
		return buffer.toString();
	}

	/**
	 * Returns the demangled string.
	 * @return the demangled string
	 */
	public String getString() {
		return string;
	}

	/**
	 * Returns the length in bytes of the demangled string.
	 * @return the length in bytes of the demangled string
	 */
	public int getLength() {
		return length;
	}

	/**
	 * Returns true if the demangled string is unicode.
	 * @return true if the demangled string is unicode
	 */
	public boolean isUnicode() {
		return unicode;
	}
}
