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

import java.awt.BorderLayout;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Document;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.DefaultDropDownSelectionDataModel;
import docking.widgets.DropDownSelectionTextField;
import docking.widgets.DropDownTextFieldDataModel.SearchMode;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.refs.AssociateSymbolCmd;
import ghidra.app.context.ListingActionContext;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.OperandFieldLocation;

public class SymbolChooserDialog extends DialogComponentProvider {

	private List<String> names;
	private DropDownSelectionTextField<String> textField;

	private LabelMgrPlugin plugin;
	private ListingActionContext context;

	public SymbolChooserDialog(LabelMgrPlugin plugin, ListingActionContext context) {
		super("Choose Label");
		this.plugin = plugin;
		this.context = context;

		Symbol symbol = getOperandLabel();
		Program program = context.getProgram();
		SymbolTable st = program.getSymbolTable();
		Address address = symbol.getAddress();
		Symbol[] symbols = st.getSymbols(address);

		names = Arrays.stream(symbols)
				.map(s -> s.getName())
				.collect(Collectors.toList());

		addWorkPanel(buildWorkPanel());

		addOKButton();
		addCancelButton();
	}

	public void show() {
		DockingWindowManager.showDialog(this);
	}

	private JComponent buildWorkPanel() {

		DefaultDropDownSelectionDataModel<String> model =
			DefaultDropDownSelectionDataModel.getStringModel(names);
		textField = new DropDownSelectionTextField<>(model);
		textField.setShowMatchingListOnEmptyText(true);
		textField.setSearchMode(SearchMode.CONTAINS);

		Document doc = textField.getDocument();
		doc.addDocumentListener(new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				updateOk();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				updateOk();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				updateOk();
			}
		});

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(textField, BorderLayout.NORTH);
		return panel;
	}

	private void updateOk() {
		setOkEnabled(!textField.getText().isEmpty());
	}

	@Override
	protected void okCallback() {
		Program program = context.getProgram();
		OperandFieldLocation location = (OperandFieldLocation) context.getLocation();
		Symbol currentSymbol = getOperandLabel();

		String newLabel = textField.getSelectedValue();
		if (newLabel == null) {
			setStatusText("Please choose a label");
			return;
		}

		if (newLabel.equals(currentSymbol.getName(true))) {
			close();
			return;
		}

		ReferenceManager refMgr = program.getReferenceManager();
		SymbolTable symTable = program.getSymbolTable();
		int opIndex = location.getOperandIndex();
		Address addr = location.getAddress();
		Address symAddr = currentSymbol.getAddress();
		Reference ref = refMgr.getReference(addr, symAddr, opIndex);

		CompoundCmd<Program> cmd = new CompoundCmd<>("Set Label");
		Namespace scope = null;
		Symbol newSym = findSymbol(symTable, newLabel, symAddr);
		if (newSym == null) {
			cmd.add(new AddLabelCmd(symAddr, newLabel, SourceType.USER_DEFINED));
		}
		else {
			scope = newSym.getParentNamespace();
			newLabel = newSym.getName();
		}
		cmd.add(new AssociateSymbolCmd(ref, newLabel, scope));

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

	private Symbol getOperandLabel() {
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

	String getChoice() {
		return textField.getSelectedValue();
	}

	void setSelectedItem(String value) {
		textField.setSelectedValue(value);
	}
}
