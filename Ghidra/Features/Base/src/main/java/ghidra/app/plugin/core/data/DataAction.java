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
import docking.tool.util.DockingToolConstants;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.util.HelpLocation;

/**
 * Base class for actions to create data types
 */
class DataAction extends ListingContextAction implements OptionsChangeListener {

	protected DataType dataType;
	protected DataPlugin plugin;
	private String actionName;
	private DummyKeyBindingsOptionsAction dummyKeybindingsAction;

	public DataAction(DataType dataType, DataPlugin plugin) {
		this("Define " + dataType.getDisplayName(), "Data", dataType, plugin);
	}

	public DataAction(String name, String group, DataType dataType, DataPlugin plugin) {
		super(name, plugin.getName(), false);
		this.actionName = name;
		this.plugin = plugin;
		this.dataType = dataType;

		setPopupMenuData(new MenuData(new String[] { "Data", dataType.getDisplayName() }, group));
		assignHelpID(dataType);

		initializeKeybinding();
	}

	private void initializeKeybinding() {
		PluginTool tool = plugin.getTool();
		dummyKeybindingsAction =
			new DummyKeyBindingsOptionsAction(actionName, getDefaultKeyStroke());
		tool.addAction(dummyKeybindingsAction);
		ToolOptions options = tool.getOptions(DockingToolConstants.KEY_BINDINGS);
		options.addOptionsChangeListener(this);
		KeyStroke keyStroke =
			options.getKeyStroke(dummyKeybindingsAction.getFullName(), getDefaultKeyStroke());
		initKeyStroke(keyStroke);
	}

	protected KeyStroke getDefaultKeyStroke() {
		return null; // we have no default, but our subclasses may
	}

	protected void initKeyStroke(KeyStroke keyStroke) {
		if (keyStroke == null) {
			return;
		}

		// we don't have a default keybinding, so any value implies user-defined
		setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
	}

	protected DockingAction getDummyKeyBindingAction() {
		return dummyKeybindingsAction;
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

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		KeyStroke keyStroke = (KeyStroke) newValue;
		if (optionName.startsWith(actionName)) {
			setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
	}

	DataType getDataType() {
		return dataType;
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
