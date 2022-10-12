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
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;

/**
 * A {@link DockingAction} for disassembling at addresses corresponding to rows in a 
 * {@link FunctionStartTableModel}.  
 */
public class DisassembleFunctionStartsAction extends DockingAction {
	private static final String ACTION_NAME = "DisassembleAction";
	private static final String MENU_TEXT = "Disassemble";
	private Program program;
	private FunctionStartTableModel model;
	private GhidraTable table;
	private Plugin plugin;

	/**
	 * Creates and action for disassembling at rows in a {@link FunctionStartTableModel} if the
	 * {@link Interpretation} of the row is {@link Interpretation#UNDEFINED}.  
	 * @param plugin owning plugin
	 * @param program source program
	 * @param table  table
	 * @param model table model
	 */
	public DisassembleFunctionStartsAction(Plugin plugin, Program program, GhidraTable table,
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
				case UNDEFINED:
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
				case UNDEFINED:
					entries.add(row.getAddress());
				default:
					break;
			}
		}
		DisassembleCommand cmd = new DisassembleCommand(entries, null, true);
		plugin.getTool().executeBackgroundCommand(cmd, program);
	}

	private void init() {
		setPopupMenuData(new MenuData(new String[] { MENU_TEXT }));
		setDescription("Disassemble at the selected rows");
		setHelpLocation(new HelpLocation(plugin.getName(), ACTION_NAME));
	}
}
