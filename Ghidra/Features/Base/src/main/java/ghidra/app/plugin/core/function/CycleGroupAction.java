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
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.program.model.data.CycleGroup;
import ghidra.program.model.data.DataType;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableLocation;
import ghidra.util.HelpLocation;

/**
 * <code>CycleGroupAction</code> cycles data through a series
 * of data types defined by a <code>CycleGroup</code>.
 */
public class CycleGroupAction extends ListingContextAction implements OptionsChangeListener {

	private FunctionPlugin plugin;
	private CycleGroup cycleGroup;

	/**
	 * Creates a new instance of the action.
	 *
	 * @param plugin Data Plugin instance
	 */
	CycleGroupAction(CycleGroup group, FunctionPlugin plugin) {
		super(group.getName(), plugin.getName(), false);
		this.plugin = plugin;
		this.cycleGroup = group;
		setPopupMenu(plugin.getDataActionMenuName(null), true);

		// register an action that allows users to edit keystrokes
		PluginTool tool = plugin.getTool();
		DockingAction action = new DummyKeyBindingsOptionsAction(cycleGroup.getName(),
			cycleGroup.getDefaultKeyStroke());
		tool.addAction(action);
		ToolOptions options = tool.getOptions(ToolConstants.KEY_BINDINGS);
		KeyStroke defaultKeyStroke = cycleGroup.getDefaultKeyStroke();
		KeyStroke keyStroke = options.getKeyStroke(action.getFullName(), defaultKeyStroke);

		if (!defaultKeyStroke.equals(keyStroke)) {
			// user-defined keystroke
			setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
		else {
			setKeyBindingData(new KeyBindingData(keyStroke));
		}

		options.addOptionsChangeListener(this);

		setHelpLocation(new HelpLocation(HelpTopics.DATA, group.getName()));
	}

	private void setPopupMenu(String name, boolean isSignatureAction) {
		setPopupMenuData(new MenuData(
			new String[] { FunctionPlugin.SET_DATA_TYPE_PULLRIGHT, "Cycle", cycleGroup.getName() },
			null, null));
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

	/**
	 * @see ghidra.framework.plugintool.DockingAction#dispose()
	 */
	@Override
	public void dispose() {
		cycleGroup = null;
		plugin = null;
		super.dispose();
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		DataType dt = plugin.getCurrentDataType(context);
		dt = cycleGroup.getNextDataType(dt, true);
		if (dt != null) {
			if (!plugin.createData(dt, context, false, false)) {
				plugin.createData(DataType.DEFAULT, context, true, false);
			}
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String name, Object oldValue, Object newValue) {
		KeyStroke keyStroke = (KeyStroke) newValue;
		if (name.startsWith(cycleGroup.getName())) {
			setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
	}
}
