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
package docking.widgets;

/**
 * Instances of this type are used to add a checkBox to a Dialog so that the dialog results
 * can be saved and reused in future uses of that dialog (e.g., "Apply to all",
 * "Remember my decision"). If the checkBox is selected, the dialog results are saved and
 * subsequent calls to show the same dialog or another dialog constructed with the same
 * instance of this object will immediately return the result instead of actually showing
 * the dialog.
 */
public class DialogRememberOption {
	private final String description;
	private int rememberedResult;
	private boolean hasRememberedResult;

	/**
	 * Constructs a new DialogRememberOption for use in an OptionDialog for adding an
	 * "Apply to all", "Remember my decision", etc. checkBox.
	 * @param description the checkBox text (e.g. "Apply to all")
	 */
	public DialogRememberOption(String description) {
		this.description = description;
	}

	/**
	 * Returns the description that will be displayed to the user.
	 * @return the description that will be displayed to the user.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Returns the result from a previous call to an OptionDialog that had this SavedDialogChoice
	 * installed.
	 * @return  the saved results from a previous call to an OptionDialog.
	 */
	public int getRememberedResult() {
		return rememberedResult;
	}

	/**
	 * Returns true if a previous call to the dialog was remembered (The user selected the
	 * checkBox)
	 * @return true if a previous call to the dialog was remembered
	 */
	public boolean hasRememberedResult() {
		return hasRememberedResult;
	}

	/**
	 * Sets the results from the dialog only if choice is true.
	 * <P>
	 * In other words, if the user selects the checkBox, then
	 * the result will be saved.  The, whenever the dialog is
	 * "shown", if there is a saved result, it will be returned
	 * instead of actually showing the dialog.
	 *
	 * @param choice the user's choice from the OptionDialog
	 */
	public void rememberResult(int choice) {
		this.hasRememberedResult = true;
		this.rememberedResult = choice;
	}
}
