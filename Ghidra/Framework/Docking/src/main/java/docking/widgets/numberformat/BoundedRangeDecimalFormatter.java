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
package docking.widgets.numberformat;

import java.awt.Toolkit;
import java.text.*;

import javax.swing.text.*;

class BoundedRangeDecimalFormatter extends NumberFormatter {

	private DocumentFilter myDocumentFilter = null;
	private final Double upperRangeValue;
	private final Double lowerRangeValue;

	BoundedRangeDecimalFormatter(Double upperRangeValue, Double lowerRangeValue,
			String numberFormat) {
		this.upperRangeValue = upperRangeValue;
		this.lowerRangeValue = lowerRangeValue;
		DecimalFormat decimalFormat = new DecimalFormat(numberFormat);
		setFormat(decimalFormat);
		setValueClass(Double.class);

		// this lets spaces in (we control other characters below in isValidText()
		setAllowsInvalid(true);
	}

	@Override
	protected DocumentFilter getDocumentFilter() {
		if (myDocumentFilter == null) {
			myDocumentFilter = new BoundedRangeDocumentFilterWrapper(super.getDocumentFilter());
		}

		return myDocumentFilter;
	}

	private class BoundedRangeDocumentFilterWrapper extends DocumentFilter {

		private final DocumentFilter wrappedFilter;

		BoundedRangeDocumentFilterWrapper(DocumentFilter wrappedFilter) {
			this.wrappedFilter = wrappedFilter;
		}

		@Override
		public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {

			StringBuilder buildy = new StringBuilder();
			Document document = fb.getDocument();
			buildy.append(document.getText(0, document.getLength()));
			buildy.delete(offset, offset + length);

			if (!isValidText(buildy.toString())) {
				warn();
				return;
			}

			wrappedFilter.remove(fb, offset, length);
		}

		@Override
		public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr)
				throws BadLocationException {

			StringBuilder buildy = new StringBuilder();
			Document document = fb.getDocument();
			buildy.append(document.getText(0, document.getLength()));
			buildy.insert(offset, string);

			if (!isValidText(buildy.toString())) {
				warn();
				return;
			}

			wrappedFilter.insertString(fb, offset, string, attr);
		}

		@Override
		public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attr)
				throws BadLocationException {

			StringBuilder buildy = new StringBuilder();
			Document document = fb.getDocument();
			buildy.append(document.getText(0, document.getLength()));
			buildy.replace(offset, offset + length, text);

			if (!isValidText(buildy.toString())) {
				warn();
				return;
			}

			wrappedFilter.replace(fb, offset, length, text, attr);
		}

		private boolean isValidText(String text) {
			if (".".equals(text) || "".equals(text)) {
				return true; // special case, let the decimal through
			}
			
			// Another special case; let the '-' through if it's
			// the first character (user is entering a negative number). But 
			// only allow this if the lower bound is negative.
			if (text.equals("-") && lowerRangeValue < 0) {
				return true;
			}

			if (containsNonNumericCharacters(text)) {
				return false;
			}

			Format format = getFormat();
			try {
				Object parseObject = format.parseObject(text);
				if (!(parseObject instanceof Number)) {
					return false;
				}
				Number number = (Number) parseObject;
				Double doubleValue = number.doubleValue();
				if (doubleValue.compareTo(upperRangeValue) > 0 ||
					doubleValue.compareTo(lowerRangeValue) < 0) {
					// no negatives or values over 1
					return false;
				}

				return true;
			}
			catch (ParseException e) {
				return false;
			}
		}

		private boolean containsNonNumericCharacters(String text) {
			int length = text.length();
			boolean seenDot = false;
			for (int i = 0; i < length; i++) {
				char theChar = text.charAt(i);
				if ('.' == theChar && !seenDot) {
					seenDot = true;
					continue; // we allow single dots through
				}

				if (!isDigit(theChar) && !isNegative(i, theChar)) {
					return true;
				}
			}
			return false;
		}

		private boolean isNegative(int i, char theChar) {
			if (i != 0) {
				return false; // '-' is only allowed as the first character
			}

			return theChar == '-';
		}

		protected boolean isDigit(char character) {
			return Character.isDigit(character);
		}

		private void warn() {
			Toolkit.getDefaultToolkit().beep();
		}
	}
}
