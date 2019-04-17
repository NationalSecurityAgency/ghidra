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
package ghidra.feature.vt.gui.actions;

import ghidra.feature.vt.api.main.VTMarkupItemApplyActionType;

public class DisplayableMarkupItemAction {

	// Apply Actions
	public static final DisplayableMarkupItemAction EXCLUDE_ACTION =
		new DisplayableMarkupItemAction("Do Not Apply", null);

	public static final DisplayableMarkupItemAction REPLACE_ACTION =
		new DisplayableMarkupItemAction("Replace", VTMarkupItemApplyActionType.REPLACE);

	public static final DisplayableMarkupItemAction ADD_ACTION = new DisplayableMarkupItemAction(
		"Add", VTMarkupItemApplyActionType.ADD); // Does the same thing as a merge.

	private String displayString;
	private VTMarkupItemApplyActionType action;

	private DisplayableMarkupItemAction(String displayString, VTMarkupItemApplyActionType action) {
		this.displayString = displayString;
		this.action = action;
	}

	public String getDisplayString() {
		return displayString;
	}

	public VTMarkupItemApplyActionType getAction() {
		return action;
	}
}
