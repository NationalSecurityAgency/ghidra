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
package docking.widgets.dialogs;

/**
 * Listener that is notified when the OK button is hit on the input dialog.
 */
public interface InputDialogListener {
	
	/**
	 * Return whether the input is accepted.
	 * @return true if the input is valid; the dialog will be popped down;
	 * false means that the dialog will remain displayed.
	 */
	public boolean inputIsValid(InputDialog dialog);

}
