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

import java.math.BigInteger;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;

/**
 * A {@link DockingAction} for disassembling at addresses corresponding to rows in a 
 * {@link FunctionStartTableModel}.  Context register values specified before training
 * will be applied before disassembly.
 */
public class DisassembleAndApplyContextAction extends DisassembleFunctionStartsAction {
	private static final String ACTION_NAME = "DisassembleAndApplyContextAction";
	private static final String MENU_TEXT = "Disassemble and Apply Context";
	private Program program;
	private FunctionStartTableModel model;
	private Plugin plugin;
	private GhidraTable table;

	/** 
	 * Creates an action for disassembling at rows in a {@link FunctionStartTableModel} if the
	 * {@link Interpretation} of the row is {@link Interpretation#UNDEFINED}.  Specified 
	 * context register values are set before disassembly.  
	 * @param plugin owning plugin
	 * @param program source program
	 * @param table table
	 * @param model table model
	 */
	public DisassembleAndApplyContextAction(Plugin plugin, Program program, GhidraTable table,
			FunctionStartTableModel model) {
		super(plugin, program, table, model);
		this.program = program;
		this.model = model;
		this.plugin = plugin;
		this.table = table;
		init();
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

		RandomForestRowObject row = model.getRandomForestRowObject();
		if (row.isContextRestricted()) {
			ProgramContext programContext = program.getProgramContext();
			List<String> regNames = row.getContextRegisterList();
			List<BigInteger> regValues = row.getContextRegisterValues();
			RegisterValue newValue = new RegisterValue(programContext.getBaseContextRegister());
			for (int i = 0; i < regNames.size(); ++i) {
				Register reg = program.getRegister(regNames.get(i));
				newValue = newValue.combineValues(new RegisterValue(reg, regValues.get(i)));
			}
			cmd.setInitialContext(newValue);
		}
		plugin.getTool().executeBackgroundCommand(cmd, program);
	}

	private void init() {
		setPopupMenuData(new MenuData(new String[] { MENU_TEXT }));
		setDescription("Apply context and disassemble at the selected rows");
		setHelpLocation(new HelpLocation(plugin.getName(), ACTION_NAME));
	}

}
