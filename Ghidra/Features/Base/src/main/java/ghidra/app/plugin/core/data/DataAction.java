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

import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.program.model.data.*;
import ghidra.util.HelpLocation;

import javax.swing.KeyStroke;

import docking.action.*;

/**
 * Base class for comment actions to edit and delete comments.
 */
class DataAction extends ListingContextAction implements OptionsChangeListener {

	protected DataType dataType;
	protected DataPlugin plugin;
	private String actionName;
	private DummyKeyBindingsOptionsAction dummyKeybindingsAction;

	public DataAction(DataType dataType, DataPlugin plugin) {
		this("Define " + dataType.getDisplayName(), "Data", dataType, plugin);
	}

	/**
	 * Constructor
	 * 
	 * @param name action name
	 * @param isKeyBindingManagee 
	 * @param owner owner of this action (the plugin name)
	 */
	public DataAction(String name, String group, DataType dataType, DataPlugin plugin) {
		super(name, plugin.getName(), false);
		this.actionName = name;
		this.plugin = plugin;
		this.dataType = dataType;

		setPopupMenuData(new MenuData(new String[] { "Data", dataType.getDisplayName() }, group));
		assignHelpID(dataType);
		setEnabled(true);

		PluginTool tool = plugin.getTool();
		dummyKeybindingsAction = new DummyKeyBindingsOptionsAction(name, getDefaultKeyStroke());
		tool.addAction(dummyKeybindingsAction);
		ToolOptions options = tool.getOptions(ToolConstants.KEY_BINDINGS);
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

	/**
	 * set the help ID according to what the data type is.
	 */
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

	/*
	 * @see docking.DockableAction#isValidContext(java.lang.Object)
	 */
	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		return plugin.isCreateDataAllowed(context);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) {
		KeyStroke keyStroke = (KeyStroke) newValue;
		if (optionName.startsWith(actionName)) {
			setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
	}
}
