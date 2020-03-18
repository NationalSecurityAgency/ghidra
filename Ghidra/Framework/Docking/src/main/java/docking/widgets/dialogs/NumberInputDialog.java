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
package docking.widgets.dialogs;

/**
 * <P>DialogComponentProvider that provides information to create a modal dialog
 * to prompt for a number (int) to be input by the user.</P>
 *
 * <P>If an initial value is specified it is not in the range of min,max, it will be set to the 
 * min.</P>
 *
 * <P>If the maximum value indicated is less than the minimum then the max
 * is the largest positive integer. Otherwise the maximum valid value is
 * as indicated.</P>
 *
 * <P>This dialog component provider class can be used by various classes and
 * therefore should not have its size or position remembered by the
 * tool.showDialog() call parameters.</P>
 * <br>To display the dialog call:
 * <pre>
 * <code>
 *     String entryType = "items";
 *     int initial = 5; // initial value in text field.
 *     int min = 1;     // minimum valid value in text field.
 *     int max = 10;    // maximum valid value in text field.
 *
 *     NumberInputDialog numInputProvider = new NumberInputProvider(entryType, initial, min, max);
 *     if (numInputProvider.show()) {
 *     	   // not cancelled
 *     	   int result = numInputProvider.getValue();
 *     }
 * </code>
 * </pre>
 */
public class NumberInputDialog extends AbstractNumberInputDialog {

	/**
	 * Constructs a new NumberInputDialog
	 *
	 * @param entryType item type the number indicates
	 *                  (i.e. "duplicates", "items", or "elements")
	 * @param initial default value displayed in the text field
	 * @param min minimum value allowed
	 */
	public NumberInputDialog(String entryType, int initial, int min) {
		this("Enter Number", buildDefaultPrompt(entryType, min, min - 1), initial, min,
			Integer.MAX_VALUE, false);
	}

	/**
	 * Constructs a new NumberInputDialog
	 *
	 * @param entryType item type the number indicates
	 *                  (i.e. "duplicates", "items", or "elements")
	 * @param initial default value displayed in the text field
	 * @param min minimum value allowed
	 * @param max maximum value allowed
	 */
	public NumberInputDialog(String entryType, int initial, int min, int max) {
		this("Enter Number", buildDefaultPrompt(entryType, min, max), initial, min, max, false);
	}

	/**
	 * Show a number input dialog
	 * @param title The title of the dialog
	 * @param prompt the prompt to display before the number input field
	 * @param initialValue the default value to display, null will leave the field blank
	 * @param min the minimum allowed value of the field
	 * @param max the maximum allowed value of the field
	 * @param showAsHex if true, the initial value will be displayed as hex
	 */
	public NumberInputDialog(String title, String prompt, Integer initialValue, int min, int max,
			boolean showAsHex) {
		super(title, prompt, initialValue, min, max, showAsHex);
	}

	/**
	 * Convert the input to an int value
	 * @return the int value
	 * @throws NumberFormatException if entered value cannot be parsed
	 * @throws IllegalStateException if the dialog was cancelled
	 */
	public int getValue() {
		return getIntValue();
	}

}
