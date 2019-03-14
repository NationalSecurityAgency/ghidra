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

import docking.ActionContext;
import docking.action.*;
import ghidra.app.cmd.data.*;
import ghidra.app.context.ListingActionContext;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CycleGroup;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.util.*;
import ghidra.util.Msg;

/**
 * <code>CycleGroupAction</code> cycles data through a series of data types
 * defined by a <code>CycleGroup</code>.
 */
public class CycleGroupAction extends DockingAction implements OptionsChangeListener {

	private DataPlugin plugin;
	private CycleGroup cycleGroup;

	/**
	 * Creates a new instance of the action.
	 *
	 * @param plugin Data Plugin instance
	 */
	CycleGroupAction(CycleGroup group, DataPlugin plugin) {
		super(group.getName(), plugin.getName(), false);
		this.plugin = plugin;
		this.cycleGroup = group;

		// register an action that allows users to edit keystrokes
		PluginTool tool = plugin.getTool();
		DockingAction action = new DummyKeyBindingsOptionsAction(cycleGroup.getName(),
			cycleGroup.getDefaultKeyStroke());
		tool.addAction(action);
		ToolOptions options = tool.getOptions(ToolConstants.KEY_BINDINGS);
		KeyStroke defaultKeyStroke = cycleGroup.getDefaultKeyStroke();
		KeyStroke keyStroke = options.getKeyStroke(action.getFullName(), defaultKeyStroke);
		options.addOptionsChangeListener(this);

		setPopupMenuData(
			new MenuData(new String[] { "Data", "Cycle", group.getName() }, null, null));

		if (!defaultKeyStroke.equals(keyStroke)) {
			// user-defined keystroke
			setUnvalidatedKeyBindingData(new KeyBindingData(keyStroke));
		}
		else {
			setKeyBindingData(new KeyBindingData(keyStroke));
		}

		setEnabled(true);
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

	/*
	 * @see docking.DockableAction#isValidContext(java.lang.Object)
	 */
	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Object contextObject = context.getContextObject();
		if (contextObject instanceof ListingActionContext) {
			return plugin.isCreateDataAllowed((ListingActionContext) contextObject);
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		if (context != null) {
			Object contextObject = context.getContextObject();

			if (contextObject instanceof ListingActionContext) {
				ListingActionContext programContextObject = (ListingActionContext) contextObject;
				cycleData(programContextObject);
				return;
			}
		}
	}

	/**
	 * Cycle the data type for the current selection or location.
	 */
	private void cycleData(ListingActionContext context) {
		Listing listing = context.getProgram().getListing();
		ProgramSelection selection = context.getSelection();
		ProgramLocation location = context.getLocation();

		// Handle selection case
		if (selection != null && !selection.isEmpty()) {
			BackgroundCommand cmd = null;
			DataType dt = null;
			Address addr = selection.getMinAddress();
			Data data = listing.getDataContaining(addr);
			InteriorSelection intSel = selection.getInteriorSelection();
			if (intSel == null) {
				dt = cycleGroup.getNextDataType(data.getDataType(), true);
				if (dt == null) {
					return;
				}
				cmd = new CreateDataBackgroundCmd(selection, dt);
			}
			else {
				int[] fromPath = intSel.getFrom().getComponentPath();
				long selectionLength = selection.getNumAddresses();
				if (selectionLength > Integer.MAX_VALUE) {
					Msg.showInfo(this, null, "Selection Too Big",
						"This operation does not support selection size > 0x7fffffff byte addresses.");
					return;
				}
				int length = (int) selectionLength;
				Data compData = data.getComponent(fromPath);
				if (compData == null) {
					return;
				}
				dt = cycleGroup.getNextDataType(compData.getDataType(), true);
				if (dt == null) {
					return;
				}
				cmd = new CreateDataInStructureBackgroundCmd(addr, fromPath, length, dt);
			}
			if (selection.getNumAddresses() < DataPlugin.BACKGROUND_SELECTION_THRESHOLD) {
				plugin.getPluginTool().execute(cmd, context.getProgram());
			}
			else {
				plugin.getPluginTool().executeBackgroundCommand(cmd, context.getProgram());
			}

			plugin.updateRecentlyUsed(dt);
		}

		// Handle single location case
		else if (location != null) {
			Address addr = location.getAddress();
			Data data = listing.getDataContaining(addr);
			if (data == null) {
				return;
			}
			int compPath[] = location.getComponentPath();
			if (compPath == null || compPath.length <= 0) {
				DataType dt = cycleGroup.getNextDataType(data.getDataType(), true);
				if (dt != null) {
					plugin.getPluginTool().execute(new CreateDataCmd(addr, dt, true, false),
						context.getProgram());
					plugin.updateRecentlyUsed(dt);
				}
			}
			else {
				Data compData = data.getComponent(compPath);
				if (compData != null) {
					DataType dt = cycleGroup.getNextDataType(compData.getDataType(), true);
					if (dt != null) {
						plugin.getPluginTool().execute(
							new CreateDataInStructureCmd(addr, compPath, dt), context.getProgram());
						plugin.updateRecentlyUsed(dt);
					}
				}
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
