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
import ghidra.app.plugin.core.navigation.FindAppliedDataTypesService;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.util.*;

/**
 * An action to show references to the field in the currently selected editor row.
 */
public class FindReferencesToStructureFieldAction extends CompositeEditorTableAction {

	private final static String ACTION_NAME = "Find Uses of";
	private final static String DESCRIPTION = "Find uses of field in the selected row";

	public FindReferencesToStructureFieldAction(CompositeEditorProvider provider) {
		super(provider, ACTION_NAME, BASIC_ACTION_GROUP, new String[] { ACTION_NAME }, null, null);
		setDescription(DESCRIPTION);
		setHelpLocation(new HelpLocation(HelpTopics.FIND_REFERENCES, "Data_Types"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!isEnabledForContext(context)) {
			return;
		}
		FindAppliedDataTypesService service = tool.getService(FindAppliedDataTypesService.class);
		if (service == null) {
			Msg.showError(this, null, "Missing Plugin",
				"The %s is not installed.\nPlease add the plugin implementing this service."
						.formatted(FindAppliedDataTypesService.class.getSimpleName()));
			return;
		}

		String fieldName = getFieldName();
		Composite composite = model.getOriginalComposite();
		Swing.runLater(() -> service.findAndDisplayAppliedDataTypeAddresses(composite, fieldName));
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
	public boolean isEnabledForContext(ActionContext context) {
		setEnabled(false);
		if (hasIncompleteFieldEntry()) {
			return false;
		}
		if (model.getSelectedComponentRows().length != 1) {
			return false;
		}

		Composite composite = model.getOriginalComposite();
		if (composite == null) {
			return false; // not sure if this can happen
		}

		String fieldName = getFieldName();
		if (fieldName == null) {
			return false;
		}

		updateMenuName(fieldName);
		return true;
	}

	private void updateMenuName(String name) {

		String menuName = ACTION_NAME + ' ' + name;
		MenuData data = getPopupMenuData().cloneData();
		data.setMenuPath(new String[] { menuName });
		setPopupMenuData(data);
	}

}
