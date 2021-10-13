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
package ghidra.app.plugin.core.label;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.refs.AssociateSymbolCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.PluginConstants;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

public class OperandLabelDialog extends DialogComponentProvider {

	private JLabel label;
	private GhidraComboBox<String> myChoice;
	private LabelMgrPlugin plugin;
	private ListingActionContext programActionContext;

	public OperandLabelDialog(LabelMgrPlugin plugin) {
		super("");
		this.plugin = plugin;
		setHelpLocation(new HelpLocation(HelpTopics.LABEL, "OperandLabelDialog"));

		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
	}

	/**
	 * Define the Main panel for the dialog here.
	 * @return JPanel the completed Main Panel
	 */
	protected JPanel buildMainPanel() {
		JPanel mainPanel = new JPanel(new PairLayout(5, 5));
		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		label = new GDLabel("Label: ");

		myChoice = new GhidraComboBox<>();
		myChoice.setName("MYCHOICE");
		myChoice.setEditable(true);
		myChoice.addActionListener(ev -> okCallback());

		mainPanel.add(label);
		mainPanel.add(myChoice);

		return mainPanel;
	}

	/**
	 * This method gets called when the user clicks on the Ok Button.  The base
	 * class calls this method.
	 */
	@Override
	protected void okCallback() {
		Program program = programActionContext.getProgram();
		ProgramLocation loc = programActionContext.getLocation();
		OperandFieldLocation location = (OperandFieldLocation) loc;
		Symbol sym = getSymbol(programActionContext);
		String currentLabel = myChoice.getText();
		if (currentLabel.equals(sym.getName(true))) {
			close();
			return;
		}

		ReferenceManager refMgr = program.getReferenceManager();
		SymbolTable symTable = program.getSymbolTable();
		int opIndex = location.getOperandIndex();
		Address addr = location.getAddress();
		Address symAddr = sym.getAddress();
		Reference ref = refMgr.getReference(addr, symAddr, opIndex);

		CompoundCmd cmd = new CompoundCmd("Set Label");
		Namespace scope = null;

		Symbol newSym = findSymbol(symTable, currentLabel, symAddr);
		if (newSym == null) {
			cmd.add(new AddLabelCmd(symAddr, currentLabel, SourceType.USER_DEFINED));
		}
		else {
			scope = newSym.getParentNamespace();
			currentLabel = newSym.getName();
		}
		cmd.add(new AssociateSymbolCmd(ref, currentLabel, scope));

		if (!plugin.getTool().execute(cmd, program)) {
			setStatusText(cmd.getStatusMsg());
			return;
		}
		close();

	}

	// Find and return the first symbol at the address with the given name. Since this is about
	// the presentation at the call or jump instruction, it doesn't matter which symbol of the
	// same name you pick.
	private Symbol findSymbol(SymbolTable symTable, String currentLabel, Address symAddr) {
		SymbolIterator symbols = symTable.getSymbolsAsIterator(symAddr);
		for (Symbol symbol : symbols) {
			if (symbol.getName(true).equals(currentLabel)) {
				return symbol;
			}
		}
		return null;
	}

	/**
	 * This method gets called when the user clicks on the Cancel Button.  The base
	 * class calls this method.
	 */
	@Override
	protected void cancelCallback() {
		close();
	}

	@Override
	public void close() {
		programActionContext = null;
		super.close();
	}

	public void setOperandLabel(ListingActionContext context) {
		programActionContext = context;
		setStatusText("");
		myChoice.clearModel();

		Symbol s = getSymbol(context);
		Symbol[] symbols = context.getProgram().getSymbolTable().getSymbols(s.getAddress());
		for (Symbol symbol : symbols) {
			myChoice.addToModel(symbol.getName(true));
		}
		setTitle("Set Label at " + s.getAddress());
		myChoice.setSelectedItem(s.getName(true));
		PluginTool tool = plugin.getTool();
		tool.showDialog(this, tool.getComponentProvider(PluginConstants.CODE_BROWSER));
	}

	private Symbol getSymbol(ListingActionContext context) {
		Program program = context.getProgram();
		OperandFieldLocation location = (OperandFieldLocation) context.getLocation();

		Address address = location.getAddress();
		int opIndex = location.getOperandIndex();

		ReferenceManager refMgr = program.getReferenceManager();

		Reference ref = refMgr.getPrimaryReferenceFrom(address, opIndex);
		if (ref != null) {
			SymbolTable st = program.getSymbolTable();
			return st.getSymbol(ref);
		}
		return null;
	}
}
