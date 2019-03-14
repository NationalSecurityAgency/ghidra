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
package docking.widgets.textfield;

import java.text.Format;
import java.text.ParseException;
import java.util.HashSet;
import java.util.Set;

import javax.swing.text.DocumentFilter;

import ghidra.util.NumericUtilities;

public class HexIntegerFormatter extends IntegerFormatter {

	public HexIntegerFormatter() {
		setValueClass(Long.class);
	}

	@Override
	protected DocumentFilter createDocumentFilter() {
		return new HexAllowedPositiveValueIntgerDocumentFilterWrapper(getFormat(),
			getOriginalDocumentFilter());
	}

	@Override
	public Object stringToValue(String text) throws ParseException {
		Long asLong = null;
		try {
			asLong = NumericUtilities.parseHexLong(text);
		}
		catch (NumberFormatException nfe) {
			ParseException parseException =
				new ParseException("Cannot parse string to a long: \"" + text + "\"", 0);
			parseException.initCause(nfe);
			throw parseException;
		}

		return super.stringToValue(asLong.toString());
	}

	/**
	 * Overridden to translate the internal value to a hex representation.
	 */
	@Override
	public String valueToString(Object value) throws ParseException {
		String valueString = super.valueToString(value);
		if ("".equals(valueString)) {
			return valueString;
		}
		return Long.toHexString(Long.valueOf(valueString));
	}

	protected static class HexAllowedPositiveValueIntgerDocumentFilterWrapper extends
			PosiviteValueIntegerDocumentFilterWrapper {

		private Set<Character> hexCharacterSet = new HashSet<Character>();

		HexAllowedPositiveValueIntgerDocumentFilterWrapper(Format format,
				DocumentFilter wrappedFilter) {
			super(format, wrappedFilter);

			hexCharacterSet.add('a');
			hexCharacterSet.add('A');
			hexCharacterSet.add('b');
			hexCharacterSet.add('B');
			hexCharacterSet.add('c');
			hexCharacterSet.add('C');
			hexCharacterSet.add('d');
			hexCharacterSet.add('D');
			hexCharacterSet.add('e');
			hexCharacterSet.add('E');
			hexCharacterSet.add('f');
			hexCharacterSet.add('F');
		}

		@Override
		protected boolean isDigit(char character) {
			if (super.isDigit(character)) {
				return true;
			}
			return hexCharacterSet.contains(character);
		}

		@Override
		protected Number parseText(String text) {
			// our formatter used in super.parseText() doesn't properly parse long values that
			// are too big, so we must do it ourselves

			try {
				return Long.parseLong(text, 16);
			}
			catch (NumberFormatException nfe) {
				return null;
			}
		}
	}
}
