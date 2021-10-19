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
package ghidra.program.model.data;

import ghidra.docking.settings.Settings;
import ghidra.program.model.mem.MemBuffer;

public interface DataTypeWithCharset extends DataType {

	/**
	 * Utility for character data types to encode a value.
	 * 
	 * @param value the character value to encode.
	 * @param buf a buffer representing the eventual destination of the bytes.
	 * @param settings the settings to use.
	 * @return the encoded value
	 * @throws DataTypeEncodeException if the value cannot be encoded
	 */
	public default byte[] encodeCharacterValue(Object value, MemBuffer buf, Settings settings)
			throws DataTypeEncodeException {
		char[] normalizedValue;
		if (value instanceof Character) {
			normalizedValue = new char[] { (Character) value };
		}
		else if (value instanceof char[]) {
			normalizedValue = (char[]) value;
			if (normalizedValue.length > 2) {
				throw new DataTypeEncodeException("char[] must represent a single code point",
					value, this);
			}
		}
		else {
			throw new DataTypeEncodeException(
				"Requires Character or char[] with a single code point", value, this);
		}
		StringDataInstance sdi = new StringDataInstance(this, settings, buf, getLength());
		try {
			return sdi.encodeReplacementFromCharValue(normalizedValue);
		}
		catch (Throwable e) {
			throw new DataTypeEncodeException(value, this, e);
		}
	}

	/**
	 * Utility for character data types to encode a representation.
	 * 
	 * @param repr the single-character string to encode.
	 * @param buf a buffer representing the eventual destination of the bytes.
	 * @param settings the settings to use.
	 * @return the encoded value
	 * @throws DataTypeEncodeException if the value cannot be encoded
	 */
	public default byte[] encodeCharacterRepresentation(String repr, MemBuffer buf,
			Settings settings) throws DataTypeEncodeException {
		StringDataInstance sdi = new StringDataInstance(this, settings, buf, getLength());
		try {
			return sdi.encodeReplacementFromCharRepresentation(repr);
		}
		catch (Throwable e) {
			throw new DataTypeEncodeException(repr, this, e);
		}
	}

	/**
	 * Get the character set for a specific data type and settings
	 * 
	 * @param settings data instance settings
	 * @return Charset for this datatype and settings
	 */
	public default String getCharsetName(Settings settings) {
		return StringDataInstance.DEFAULT_CHARSET_NAME;
	}
}
