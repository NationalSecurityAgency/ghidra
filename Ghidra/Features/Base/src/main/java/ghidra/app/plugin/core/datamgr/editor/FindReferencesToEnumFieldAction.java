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
package ghidra.app.plugin.core.datamgr.editor;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.MenuData;
import ghidra.app.plugin.core.datamgr.actions.AbstractFindReferencesToFieldAction;
import ghidra.app.services.FieldMatcher;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.data.DataType;

/**
 * Finds references to a member of an enum.
 */
public class FindReferencesToEnumFieldAction extends AbstractFindReferencesToFieldAction {

	public FindReferencesToEnumFieldAction(Plugin plugin) {
		super(plugin);
	}

	@Override
	protected DataTypeAndFields getSelectedType(ActionContext context) {

		ComponentProvider provider = context.getComponentProvider();
		if (!(provider instanceof EnumEditorProvider enumProvider)) {
			return null;
		}

		String fieldName = enumProvider.getSelectedFieldName();
		if (fieldName == null) {
			return null;
		}

		updateMenuName(fieldName);
		DataType dt = enumProvider.getEnum();
		return new DataTypeAndFields(dt, new String[] { fieldName });
	}

	@Override
	protected FieldMatcher createFieldMatcher(DataTypeAndFields typeAndFields) {
		DataType dt = typeAndFields.dataType();
		String field = typeAndFields.fieldNames()[0];
		return new FieldMatcher(dt, field);
	}

	private void updateMenuName(String name) {
		String menuName = BASE_ACTION_NAME + ' ' + name;
		MenuData data = getPopupMenuData().cloneData();
		data.setMenuPath(new String[] { menuName });
		setPopupMenuData(data);
	}

}
