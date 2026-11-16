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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.dialogs.ObjectChooserDialog;
import docking.widgets.label.GLabel;
import ghidra.app.util.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;

public class ThunkReferenceAddressDialog extends DialogComponentProvider {

	private PluginTool tool;

	private JTextField refFunctionField;

	private Address refAddress;
	private Symbol refSymbol;

	private Program program;

	public ThunkReferenceAddressDialog(PluginTool tool) {
		super("Thunk Destination Function/Address", true, true, true, false);
		this.tool = tool;
		setHelpLocation(new HelpLocation(HelpTopics.LABEL, "AddEditDialog"));

		addWorkPanel(create());

		setFocusComponent(refFunctionField);

		addOKButton();
		addCancelButton();

		setDefaultButton(okButton);

		setRememberSize(false);
		setRememberLocation(false);
	}

	public void showDialog(Program p, Address entry, Address referencedFunctionAddr) {

		this.program = p;
		String defaultStr = "";
		if (referencedFunctionAddr != null) {
			defaultStr = Long.toHexString(referencedFunctionAddr.getAddressableWordOffset());
		}
		refFunctionField.setText(defaultStr);

		tool.showDialog(this);
	}

	public void showDialog(Program p, Address entry, Symbol symbol) {

		this.program = p;
		String defaultStr = "";
		if (symbol != null) {
			defaultStr = symbol.getName(true);
		}
		refFunctionField.setText(defaultStr);

		tool.showDialog(this);
	}

	/**
	 * @return reference memory address
	 */
	public Address getAddress() {
		return refAddress;
	}

	/**
	 * @return reference symbol
	 */
	public Symbol getSymbol() {
		return refSymbol;
	}

	@Override
	protected void okCallback() {

		String text = refFunctionField.getText().trim();
		if (text.isEmpty()) {
			setStatusText("Destination cannot be blank");
			return;
		}

		refAddress = program.getAddressFactory().getAddress(text);
		if (refAddress == null) {
			refSymbol = getSymbolForText(text);
			if (refSymbol == null) {
				setStatusText("Invalid thunk reference address or name specified");
				return;
			}
			refAddress = refSymbol.getAddress();
		}

		refSymbol = maybeUpgradeToFunctionSymbol(refAddress, refSymbol);
		if (!isValid(refAddress, refSymbol)) {
			return;
		}

		close();
	}

	private boolean isValid(Address addr, Symbol s) {
		if (s == null) {
			setStatusText("Function not found at address: " + addr);
			return false;
		}
		if (refSymbol.isExternal() || s.getSymbolType() == SymbolType.FUNCTION) {
			// Externals and functions are valid
			return true;
		}

		if (addr == null) {
			return false;
		}

		Listing listing = program.getListing();
		if (listing.getFunctionContaining(addr) != null) {
			setStatusText("Address cannot be within function: " + addr);
			return false;
		}

		return true;
	}

	private Symbol maybeUpgradeToFunctionSymbol(Address addr, Symbol s) {
		if (s != null) {
			if (s.getSymbolType() == SymbolType.FUNCTION) {
				return s;
			}
			addr = s.getAddress();
		}
		else {
			// Ignore low-bit for certain languages (e.g., Thumb)
			addr = PseudoDisassembler.getNormalizedDisassemblyAddress(program, addr);
		}

		Listing listing = program.getListing();
		Function refFunction = listing.getFunctionAt(addr);
		if (refFunction != null) {
			// Switch to use function symbol instead of CODE symbol
			return refFunction.getSymbol();
		}

		return s;
	}

	/**
	 * Get the code/function symbol which corresponds to the specified 
	 * text entry which may optionally include a namespace
	 * @param text symbol name
	 * @return symbol or null if multiple symbols found
	 * 
	 */
	private Symbol getSymbolForText(String text) {

		SymbolPath symbolPath = new SymbolPath(text);
		Namespace namespace = getNamespace(symbolPath);

		List<Symbol> symbols = getSymbols(symbolPath, namespace);
		symbols = filterSymbols(symbols);
		if (namespace == null) {
			// look for original external symbols not indexed by symbol table
			symbols.addAll(findOriginalExternalSymbols(text));
		}
		if (symbols.isEmpty()) {
			return null;
		}
		if (symbols.size() == 1) {
			return symbols.get(0);
		}
		return pickSymbol(symbols, symbolPath.getName());

	}

	private List<Symbol> filterSymbols(List<Symbol> symbols) {
		return symbols.stream().filter(s -> isValidSymbol(s)).collect(Collectors.toList());
	}

	private Symbol pickSymbol(List<Symbol> symbols, String name) {
		List<ThunkSymbolDecorator> list =
			symbols.stream().map(ThunkSymbolDecorator::new).collect(Collectors.toList());
		ObjectChooserDialog<ThunkSymbolDecorator> dialog =
			new ObjectChooserDialog<ThunkSymbolDecorator>("Choose Which \"" + name + "\"",
				ThunkSymbolDecorator.class, list, "getAddress", "getLibrary", "getNamespace",
				"getSignature");

		dialog.setPreferredWidth(820);
		dialog.setPreferredColumnWidths(120, 150, 150, 400);
		tool.showDialog(dialog);
		ThunkSymbolDecorator selectedObject = dialog.getSelectedObject();
		if (selectedObject == null) {
			close();
			return null;
		}
		return selectedObject.getSymbol();
	}

	private List<Symbol> getSymbols(SymbolPath symbolPath, Namespace namespace) {
		SymbolTable symbolTable = program.getSymbolTable();
		if (namespace != null) {
			return symbolTable.getSymbols(symbolPath.getName(), namespace);
		}
		SymbolIterator it = symbolTable.getSymbols(symbolPath.getName());
		List<Symbol> list = new ArrayList<>();
		it.forEach(list::add);
		return list;
	}

	private boolean isValidSymbol(Symbol s) {
		// valid symbols are function symbols (internal or external) and external labels
		SymbolType symbolType = s.getSymbolType();
		if (symbolType == SymbolType.FUNCTION) {
			return true;
		}
		if (symbolType == SymbolType.LABEL) {
			return s.isExternal();
		}
		return false;
	}

	private Namespace getNamespace(SymbolPath symbolPath) {
		String parentNs = symbolPath.getParentPath();
		if (parentNs == null) {
			return null;
		}

		List<Namespace> namespaces = NamespaceUtils.getNamespaceByPath(program, null, parentNs);

		if (namespaces.size() > 1) {
			// assume local symbol was specified
			Msg.showError(this, getComponent(), "Invalid Namespace",
				"Invalid namespace specified, expected Class or Namespace");
		}

		return namespaces.isEmpty() ? null : namespaces.get(0);
	}

	private List<Symbol> findOriginalExternalSymbols(String name) {
		List<Symbol> list = new ArrayList<>();
		// must examine each external since secondary/original name
		// is not indexed within symbol table
		SymbolTable symbolTable = program.getSymbolTable();
		ExternalManager externalManager = program.getExternalManager();
		for (Symbol s : symbolTable.getExternalSymbols()) {
			SymbolType type = s.getSymbolType();
			if (type == SymbolType.FUNCTION || type == SymbolType.LABEL) {
				ExternalLocation externalLocation = externalManager.getExternalLocation(s);
				String originalName = externalLocation.getOriginalImportedName();
				if (name.equals(originalName)) {
					list.add(s);
				}
			}
		}
		return list;
	}

	/**
	 * Define the Main panel for the dialog here.
	 */
	private JPanel create() {

		JPanel mainPanel = new JPanel(new PairLayout(5, 5));
		refFunctionField = new JTextField(20);
		refFunctionField.getAccessibleContext().setAccessibleName("Reference Function");
		mainPanel.add(new GLabel("Destination Function/Address:"));
		mainPanel.add(refFunctionField);

		mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10));
		mainPanel.getAccessibleContext().setAccessibleName("Think Reference Address");
		return mainPanel;
	}

}
