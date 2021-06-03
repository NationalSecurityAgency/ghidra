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

import java.math.BigInteger;

/**
 * <P>DialogComponentProvider that provides information to create a modal dialog
 * to prompt for a number larger than an {@code int} or {@code long} to be input by the user.</P>
 *
 * <P>Note: if you intend to only work with number values less than {@link Integer#MAX_VALUE}, 
 * then you should use the {@link NumberInputDialog}.
 *
 * <P>If an initial value is specified it is not in the range of min,max, it will be set to the min.</P>
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
 *     BigInteger initial = 5; // initial value in text field
 *     BigInteger min = BigInteger.valueOf(1);     // minimum valid value in text field
 *     BigInteger max = BigInteger.valueOf(10);    // maximum valid value in text field
 *
 *     BigIntegerNumberInputDialog provider = 
 *     	new BigIntegerNumberInputDialog("Title", entryType, initial, min, max);
 *     if (numInputProvider.show()) {
 *     	   // not cancelled
 *     	   BigInteger result = provider.getValue();
 *     	   long longResult = provider.getLongValue();
 *     }
 * </code>
 * </pre>
 */
public class BigIntegerNumberInputDialog extends AbstractNumberInputDialog {

	public BigIntegerNumberInputDialog(String title, String prompt, BigInteger initialValue,
			BigInteger min,
			BigInteger max,
			boolean showAsHex) {
		super(title, prompt, initialValue, min, max, showAsHex);
	}

	/**
	 * Get the current input value
	 * @return the value
	 * @throws NumberFormatException if entered value cannot be parsed
	 * @throws IllegalStateException if the dialog was cancelled
	 */
	public BigInteger getValue() {
		return getBigIntegerValue();
	}
}
