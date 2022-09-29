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
package ghidra.machinelearning.functionfinding;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;

/**
 * A {@link DockingAction} for creating functions from rows in a {@link FunctionStartTableModel}.
 * When performed on a selection, functions are created at all rows in the selection whose 
 * {@link Interpretation} is {@link Interpretation#BLOCK_START}.
 */
public class CreateFunctionsAction extends DockingAction {
	private static final String MENU_TEXT = "Create Function(s)";
	private static final String ACTION_NAME = "CreateFunctionsAction";
	private Program program;
	private FunctionStartTableModel model;
	private GhidraTable table;
	private Plugin plugin;

	/**
	 * Constructs an action for creating functions.
	 * @param plugin plugin
	 * @param program source program
	 * @param table table
	 * @param model table model
	 */
	public CreateFunctionsAction(Plugin plugin, Program program, GhidraTable table,
			FunctionStartTableModel model) {
		super(ACTION_NAME, plugin.getName());
		this.program = program;
		this.model = model;
		this.plugin = plugin;
		this.table = table;
		init();
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		for (FunctionStartRowObject row : model.getRowObjects(table.getSelectedRows())) {
			switch (row.getCurrentInterpretation()) {
				case BLOCK_START:
					return true;
				default:
					break;
			}
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		AddressSet entries = new AddressSet();
		for (FunctionStartRowObject row : model.getRowObjects(table.getSelectedRows())) {
			switch (row.getCurrentInterpretation()) {
				case BLOCK_START:
					entries.add(row.getAddress());
				default:
					break;
			}
		}
		CreateFunctionCmd cmd = new CreateFunctionCmd(entries);
		plugin.getTool().executeBackgroundCommand(cmd, program);
	}

	private void init() {
		setPopupMenuData(new MenuData(new String[] { MENU_TEXT }));
		setDescription(
			String.format("Creates functions at all %s rows", Interpretation.BLOCK_START.name()));
		setHelpLocation(new HelpLocation(plugin.getName(), ACTION_NAME));
	}

}
