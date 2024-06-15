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
package ghidra.app.plugin.core.datamgr.actions;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.plugin.core.navigation.FindAppliedDataTypesService;
import ghidra.app.services.FieldMatcher;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.data.DataType;
import ghidra.util.*;

public abstract class AbstractFindReferencesToFieldAction extends DockingAction {

	// The base action name will be used to create the menu item by appending the field name
	public static final String BASE_ACTION_NAME = "Find Uses of";

	private Plugin plugin;

	public AbstractFindReferencesToFieldAction(Plugin plugin) {
		super(BASE_ACTION_NAME, plugin.getName(), KeyBindingType.SHARED);
		this.plugin = plugin;

		String menuGroup = "ZVeryLast"; // it's own group; on the bottom
		setPopupMenuData(new MenuData(new String[] { "Find Uses of Field..." }, null, menuGroup));

		setHelpLocation(new HelpLocation("LocationReferencesPlugin", "Data_Types"));
	}

	protected abstract DataTypeAndFields getSelectedType(ActionContext context);

	protected abstract FieldMatcher createFieldMatcher(DataTypeAndFields typeAndFields);

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return getSelectedType(context) != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		ServiceProvider serviceProvider = plugin.getTool();
		FindAppliedDataTypesService service =
			serviceProvider.getService(FindAppliedDataTypesService.class);
		if (service == null) {
			Msg.showError(this, null, "Missing Plugin",
				"The %s is not installed.\nPlease add the plugin implementing this service."
						.formatted(FindAppliedDataTypesService.class.getSimpleName()));
			return;
		}

		DataTypeAndFields typeAndFields = getSelectedType(context);
		FieldMatcher fieldMatcher = createFieldMatcher(typeAndFields);
		if (fieldMatcher == null) {
			return; // user cancelled
		}

		DataType dt = fieldMatcher.getDataType();
		Swing.runLater(() -> service.findAndDisplayAppliedDataTypeAddresses(dt, fieldMatcher));
	}

	public record DataTypeAndFields(DataType dataType, String[] fieldNames) {
		// record
	}
}
