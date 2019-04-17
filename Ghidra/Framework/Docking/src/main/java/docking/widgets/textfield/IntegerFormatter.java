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
package docking.widgets.textfield;

import java.awt.Toolkit;
import java.text.*;

import javax.swing.text.*;

public class IntegerFormatter extends NumberFormatter {

	private DocumentFilter myDocumentFilter = null;

	public IntegerFormatter() {
		super();
		NumberFormat numberFormat = NumberFormat.getNumberInstance();
		numberFormat.setGroupingUsed(false);
		numberFormat.setParseIntegerOnly(true);
		setFormat(numberFormat);
		setValueClass(Integer.class);

		// this lets spaces in (we control other characters below in isValidText()
		setAllowsInvalid(true);
	}

	@Override
	protected DocumentFilter getDocumentFilter() {
		if (myDocumentFilter == null) {
			myDocumentFilter = createDocumentFilter();
		}

		return myDocumentFilter;
	}

	protected DocumentFilter createDocumentFilter() {
		return new PosiviteValueIntegerDocumentFilterWrapper(getFormat(),
			getOriginalDocumentFilter());
	}

	protected DocumentFilter getOriginalDocumentFilter() {
		return super.getDocumentFilter();
	}

	protected static class PosiviteValueIntegerDocumentFilterWrapper extends DocumentFilter {

		protected final DocumentFilter wrappedFilter;
		protected final Format format;

		PosiviteValueIntegerDocumentFilterWrapper(Format format, DocumentFilter wrappedFilter) {
			this.format = format;
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

		protected boolean isValidText(String text) {
			if (text.indexOf('-') != -1) {
				return false;
			}

			if ("".equals(text)) {
				return true;
			}

			if (containsNonNumericCharacters(text)) {
				return false;
			}

			Number number = parseText(text);
			if (number == null) {
				return false;
			}

			Long longValue = number.longValue();
			if (longValue.compareTo(0L) < 0) {
				return false; // no negatives
			}
			return true;
		}

		private boolean containsNonNumericCharacters(String text) {
			int length = text.length();
			for (int i = 0; i < length; i++) {
				char theChar = text.charAt(i);
				if (!isDigit(theChar)) {
					return true;
				}
			}
			return false;
		}

		protected boolean isDigit(char character) {
			return Character.isDigit(character);
		}

		protected Number parseText(String text) {
			try {
				Object parseObject = format.parseObject(text);
				if (!(parseObject instanceof Number)) {
					return null;
				}
				return (Number) parseObject;
			}
			catch (ParseException pe) {
				return null;
			}
			catch (NumberFormatException nfe) {
				return null;
			}
		}

		private void warn() {
			Toolkit.getDefaultToolkit().beep();
		}
	}
}
