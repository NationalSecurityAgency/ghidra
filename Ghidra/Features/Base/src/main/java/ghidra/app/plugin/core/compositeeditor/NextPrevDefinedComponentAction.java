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
package ghidra.app.plugin.core.compositeeditor;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.util.HelpLocation;

/**
 * An action that lets the user jump to the next row that has a defined type.
 */
public class NextPrevDefinedComponentAction extends CompositeEditorTableAction {

	private boolean forward;

	public NextPrevDefinedComponentAction(CompositeEditorProvider<?, ?> provider, boolean forward) {
		super(provider, getName(forward));

		this.forward = forward;

		MenuData data = new MenuData(new String[] { getName(forward) });
		data.setMenuGroup(BASIC_ACTION_GROUP + "_2"); // put below the basic action group
		setPopupMenuData(data);

		setKeyBindingData(new KeyBindingData(forward ? "Control Down" : "Control Up"));

		setHelpLocation(
			new HelpLocation(provider.getHelpTopic(), "Structure_Editor_Go_To_Next_Defined"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		provider.goToNextDefinedRow(forward);
	}

	private static String getName(boolean forward) {
		return "Go to " + (forward ? "Next" : "Previous") + " Defined Type";
	}
}
