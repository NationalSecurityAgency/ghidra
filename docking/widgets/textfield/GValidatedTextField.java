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

import java.awt.Toolkit;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JTextField;
import javax.swing.text.*;

import ghidra.util.NumericUtilities;

public class GValidatedTextField extends JTextField {
	public GValidatedTextField(List<TextValidator> validators, String value, int columns) {
		super(new ValidatedDocument(validators), value, columns);
	}

	public GValidatedTextField(String value, int columns) {
		this(null, value, columns);
	}

	public void addValidator(TextValidator validator) {
		ValidatedDocument d = (ValidatedDocument) getDocument();
		d.addValidator(validator);
	}

	public void removeValidator(TextValidator validator) {
		ValidatedDocument d = (ValidatedDocument) getDocument();
		d.removeValidator(validator);
	}

	public void addValidationMessageListener(ValidationMessageListener listener) {
		ValidatedDocument d = (ValidatedDocument) getDocument();
		d.addValidationMessageListener(listener);
	}

	public void removeValidationMessageListener(ValidationMessageListener listener) {
		ValidatedDocument d = (ValidatedDocument) getDocument();
		d.removeValidationMessageListener(listener);
	}

	public static class ValidatedDocument extends PlainDocument {
		protected Toolkit toolkit = Toolkit.getDefaultToolkit();
		private List<TextValidator> validators = new ArrayList<TextValidator>();
		private List<ValidationMessageListener> listeners =
			new ArrayList<ValidationMessageListener>();

		public ValidatedDocument(List<TextValidator> validators) {
			if (validators != null) {
				this.validators.addAll(validators);
			}
		}

		public ValidatedDocument() {
			this(null);
		}

		public void addValidator(TextValidator validator) {
			validators.add(0, validator);
		}

		public void removeValidator(TextValidator validator) {
			validators.remove(validator);
		}

		public void addValidationMessageListener(ValidationMessageListener listener) {
			listeners.add(listener);
		}

		public void removeValidationMessageListener(ValidationMessageListener listener) {
			listeners.add(listener);
		}

		protected void validate(String oldText, String newText) throws ValidationFailedException {
			for (TextValidator v : validators) {
				v.validate(oldText, newText);
			}
		}

		protected void message(String msg) {
			for (ValidationMessageListener l : listeners) {
				l.message(msg);
			}
		}

		@Override
		public void insertString(int offs, String str, AttributeSet a) throws BadLocationException {
			String oldText = getText(0, getLength());
			String newText = oldText.substring(0, offs) + str + oldText.substring(offs);
			try {
				validate(oldText, newText);
				super.insertString(offs, str, a);
				message("");
			}
			catch (ValidationFailedException e) {
				message(e.getMessage());
				toolkit.beep();
			}
		}
	}

	public static interface TextValidator {
		public void validate(String oldText, String newText) throws ValidationFailedException;
	}

	public static interface ValidationMessageListener {
		public void message(String msg);
	}

	public static class ValidationFailedException extends Exception {
		public ValidationFailedException(String msg) {
			super(msg);
		}

		public ValidationFailedException(Throwable cause) {
			super(cause.getMessage(), cause);
		}

		public ValidationFailedException(String msg, Throwable cause) {
			super(msg, cause);
		}
	}

	public static class LongField extends GValidatedTextField {
		public LongField(List<TextValidator> validators, String value, int columns) {
			super(validators, value, columns);
			boolean hasLongValidator = false;
			if (validators != null) {
				for (TextValidator v : validators) {
					if (v instanceof LongValidator) {
						hasLongValidator = true;
					}
				}
			}
			if (!hasLongValidator) {
				addValidator(new LongValidator());
			}
		}

		public LongField(String value, int columns) {
			this(null, value, columns);
		}

		public LongField(String value) {
			this(null, value, 0);
		}

		public LongField(int columns) {
			this(null, "0", columns);
		}

		public long getValue() {
			// NOTE: This should never throw NumberFormatException, since it's already validated
			return NumericUtilities.parseLong(getText());
		}

		public static class LongValidator implements TextValidator {
			@Override
			public void validate(String oldText, String newText) throws ValidationFailedException {
				try {
					long oldLong = NumericUtilities.parseLong(oldText);
					long newLong = NumericUtilities.parseLong(newText);
					validateLong(oldLong, newLong);
				}
				catch (NumberFormatException e) {
					throw new ValidationFailedException(e);
				}
			}

			public void validateLong(long oldLong, long newLong) throws ValidationFailedException {
			}
		}
	}

	public static class MaxLengthField extends GValidatedTextField {
		public MaxLengthField(List<TextValidator> validators, String value, int columns) {
			super(validators, value, columns);
			setDocument(new MaxLengthDocument(validators));
			// Use columns as maximum length
		}

		public MaxLengthField(String value, int columns) {
			this(null, value, columns);
		}

		public MaxLengthField(int columns) {
			this(null, null, columns);
		}

		protected class MaxLengthDocument extends ValidatedDocument {
			public MaxLengthDocument(List<TextValidator> validators) {
				super(validators);
			}

			@Override
			public void insertString(int offs, String str, AttributeSet a)
					throws BadLocationException {
				if (str == null) {
					return;
				}
				int oldLength = getLength();
				int max = getColumns();
				if (oldLength + str.length() > max) {
					toolkit.beep();
					message("Exceeded " + max + " characters.");
					str = str.substring(0, max - oldLength);
				}
				super.insertString(offs, str, a);
			}
		}
	}
}
