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
import docking.action.MenuData;
import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.textfield.integer.IntegerFormat;
import ghidra.util.HelpLocation;

public class JumpToOffsetAction extends CompositeEditorTableAction {

	protected JumpToOffsetAction(StructureEditorProvider provider) {
		super(provider, "Jump to Offset");

		MenuData data = new MenuData(new String[] { "Jump to Offset" });
		data.setMenuGroup(BASIC_ACTION_GROUP + "_Jump");
		data.setMenuSubGroup("3");
		setPopupMenuData(data);

		setHelpLocation(
			new HelpLocation(provider.getHelpTopic(), "Structure_Editor_Go_To_Offset"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		NumberInputDialog dialog = new NumberInputDialog("Offset", 0, 0, Integer.MAX_VALUE);
		dialog.setHelpLocation(getHelpLocation());
		dialog.setTitle("Enter Offset");
		dialog.setPrompt("Enter offset:");

		// make the 0x optional; users will have to manually change modes
		dialog.setAutoSwitchMode(false);
		boolean isHex = model.isShowingNumbersInHex();
		if (isHex) {
			dialog.setMode(IntegerFormat.HEX);
			dialog.setInputAsText(""); // have no initial value
			dialog.setDefaultMessage("");
		}

		if (!dialog.show()) {
			return; // cancelled
		}

		int offset = dialog.getValue();
		((StructureEditorProvider) provider).goToOffset(offset);
	}

}
