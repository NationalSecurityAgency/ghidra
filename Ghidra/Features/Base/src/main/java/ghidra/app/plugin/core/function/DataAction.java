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
package ghidra.app.plugin.core.function;

import javax.swing.KeyStroke;

import docking.action.*;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.program.model.data.DataType;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableLocation;
import ghidra.util.HelpLocation;

/**
 * Base class for comment actions to edit and delete comments.
 */
class DataAction extends ListingContextAction implements OptionsChangeListener {

	private final String group;
	protected DataType dataType;
	protected FunctionPlugin plugin;
	private String actionName;
	private DummyKeyBindingsOptionsAction dummyKeybindingsAction;

	public DataAction(DataType dataType, FunctionPlugin plugin) {
		this("Define " + dataType.getDisplayName(), "Function", dataType, plugin);
		setHelpLocation(new HelpLocation(plugin.getName(), "DataType"));
	}

	public DataAction(String name, String group, DataType dataType, FunctionPlugin plugin) {
		super(name, plugin.getName(), false);
		this.actionName = name;
		this.group = group;
		this.plugin = plugin;
		this.dataType = dataType;

		setPopupMenu(plugin.getDataActionMenuName(null), true);
		setHelpLocation(new HelpLocation(plugin.getName(), "DataType"));
		initializeKeybinding();
	}

	private void initializeKeybinding() {
		PluginTool tool = plugin.getTool();
		dummyKeybindingsAction =
			new DummyKeyBindingsOptionsAction(actionName, getDefaultKeyStroke());
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

	void setPopupMenu(String name, boolean isSignatureAction) {
		setPopupMenuData(new MenuData(
			new String[] { FunctionPlugin.SET_DATA_TYPE_PULLRIGHT, dataType.getDisplayName() },
			group));
	}

	@Override
	public void dispose() {
		dataType = null;
		plugin = null;
		super.dispose();
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection() || context.getAddress() == null) {
			return false;
		}
		ProgramLocation location = context.getLocation();
		if (plugin.isValidDataLocation(location)) {
			setPopupMenu(plugin.getDataActionMenuName(location), true);
			return true;
		}
		if (location instanceof VariableLocation) {
			setPopupMenu(plugin.getDataActionMenuName(location), false);
			return true;
		}
		return false;
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		plugin.createData(dataType, context, true);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		KeyStroke keyStroke = (KeyStroke) newValue;
		if (optionName.startsWith(actionName)) {
			setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
	}
}
