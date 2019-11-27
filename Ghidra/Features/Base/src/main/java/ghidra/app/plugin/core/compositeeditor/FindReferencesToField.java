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

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.plugin.core.navigation.FindAppliedDataTypesService;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * An action to show references to the field in the currently selected editor row
 */
public class FindReferencesToField extends CompositeEditorTableAction {

	public final static String ACTION_NAME = "Find Uses of";
	private final static String GROUP_NAME = BASIC_ACTION_GROUP;
	private final static String DESCRIPTION = "Find uses of field in the selected row";
	private static String[] popupPath = new String[] { ACTION_NAME };

	public FindReferencesToField(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, popupPath, null, null);
		setDescription(DESCRIPTION);
		adjustEnablement();
		setHelpLocation(new HelpLocation(HelpTopics.FIND_REFERENCES, "Data_Types"));
	}

	@Override
	public void actionPerformed(ActionContext context) {

		FindAppliedDataTypesService service = tool.getService(FindAppliedDataTypesService.class);
		if (service == null) {
			Msg.showError(this, null, "Missing Plugin",
				"The FindAppliedDataTypesService is not installed.\n" +
					"Please add the plugin implementing this service.");
			return;
		}

		String fieldName = getFieldName();
		Composite composite = model.getOriginalComposite();
		SwingUtilities.invokeLater(
			() -> service.findAndDisplayAppliedDataTypeAddresses(composite, fieldName));
	}

	private String getFieldName() {
		int[] rows = model.getSelectedComponentRows();
		if (rows.length == 0) {
			return null;
		}

		int row = rows[0];
		DataTypeComponent dtComponet = model.getComponent(row);
		String fieldName = dtComponet.getFieldName();
		return fieldName;
	}

	@Override
	public void adjustEnablement() {
		setEnabled(false);
		if (model.getSelectedComponentRows().length != 1) {
			return;
		}

		Composite composite = model.getOriginalComposite();
		if (composite == null) {
			return; // not sure if this can happen
		}

		String fieldName = getFieldName();
		if (fieldName == null) {
			return;
		}

		setEnabled(true);
		updateMenuName(fieldName);
	}

	private void updateMenuName(String name) {

		String menuName = ACTION_NAME + ' ' + name;
		MenuData data = getPopupMenuData().cloneData();
		data.setMenuPath(new String[] { menuName });
		setPopupMenuData(data);
	}

}
