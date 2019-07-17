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
package ghidra.app.plugin.core.data;

import javax.swing.KeyStroke;

import docking.action.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.program.model.data.*;
import ghidra.util.HelpLocation;

/**
 * Base class for actions to create data types
 */
class DataAction extends ListingContextAction {

	protected DataType dataType;
	protected DataPlugin plugin;

	public DataAction(DataType dataType, DataPlugin plugin) {
		this("Define " + dataType.getDisplayName(), "Data", dataType, plugin);
	}

	/**
	 * Constructor
	 * 
	 * @param name action name
	 * @param group the action's group
	 * @param dataType the data type used by this action
	 * @param plugin the plugin that owns this action
	 */
	public DataAction(String name, String group, DataType dataType, DataPlugin plugin) {
		super(name, plugin.getName(), KeyBindingType.SHARED);
		this.plugin = plugin;
		this.dataType = dataType;

		setPopupMenuData(new MenuData(new String[] { "Data", dataType.getDisplayName() }, group));
		assignHelpID(dataType);
		initKeyStroke(getDefaultKeyStroke());
	}

	protected KeyStroke getDefaultKeyStroke() {
		return null; // we have no default, but our subclasses may
	}

	protected void initKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return;
		}

		setKeyBindingData(new KeyBindingData(keyStroke));
	}

	DataType getDataType() {
		return dataType;
	}

	@Override
	public void dispose() {
		dataType = null;
		plugin = null;
		super.dispose();
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		plugin.doCreateData(context, dataType);
		return;
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		return plugin.isCreateDataAllowed(context);
	}

	// Set the help ID according to the data type
	private void assignHelpID(DataType dt) {
		String helpID = "Favorites";

		if (dt instanceof Structure) {
			helpID = "Structure";
		}
		else if (dt instanceof Union) {
			helpID = "Union";
		}
		else if (dt instanceof Pointer) {
			helpID = "Define_Pointer";
		}
		else if (dt instanceof Dynamic) {
			helpID = "DynamicDataType";
		}

		setHelpLocation(new HelpLocation(plugin.getName(), helpID));
	}
}
