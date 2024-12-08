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
package docking.widgets.values;

import ghidra.util.StatusListener;

/**
 * Interface for validating values in a {@link GValuesMap}
 */
public interface ValuesMapValidator {

	/**
	 * Validates one or more values in the given ValuesMap. This is used by the ValuesMapDialog
	 * to validate values when the user presses the "Ok" button. If it returns true, the dialog
	 * will close. Otherwise, the dialog will remain visible, displaying the error message that
	 * was reported to the given StatusListener.
	 * @param values the ValuesMap whose values are to be validated
	 * @param statusListener a {@link StatusListener} to report validation errors back to
	 * the dialog
	 * @return true if the values pass the validation check.
	 */
	public boolean validate(GValuesMap values, StatusListener statusListener);
}
