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

import java.util.Iterator;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.label.GLabel;
import ghidra.app.util.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;
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
			try {
				refSymbol = getSymbolForText(text);
				if (refSymbol == null) {
					Msg.showError(this, getComponent(), "Ambiguous Symbol Name",
						"Specified symbol is ambiguous.  Try full namespace name, " +
							"mangled name or address.");
					return;
				}
			}
			catch (NotFoundException e) {
				Msg.showError(this, getComponent(), "Invalid Entry Error",
					"Invalid thunk reference address or name specified: " + text);
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

		if (s != null) {
			if (refSymbol.isExternal() || s.getSymbolType() == SymbolType.FUNCTION) {
				// Externals and functions are valid
				return true;
			}
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
	 * @throws NotFoundException if no matching symbols were found 
	 * 
	 */
	private Symbol getSymbolForText(String text) throws NotFoundException {

		SymbolTable symbolTable = program.getSymbolTable();

		SymbolPath symbolPath = new SymbolPath(text);
		Namespace namespace = getNamespace(symbolPath);

		Iterator<Symbol> symbolIterator;
		if (namespace == null) {
			symbolIterator = symbolTable.getSymbols(text);
		}
		else {
			symbolIterator = symbolTable.getSymbols(symbolPath.getName(), namespace).iterator();
		}
		Symbol symbol = null;
		try {
			symbol = findRefSymbol(symbolIterator);
			if (symbol == null) {
				return null; // multiple symbols found
			}
		}
		catch (NotFoundException e) {
			// ignore
		}

		Symbol candidateSymbol2 = null;
		if (namespace == null) {
			// look for original external symbols not indexed by symbol table
			try {
				candidateSymbol2 = findOriginalExternalSymbol(text);
				if (candidateSymbol2 == null) {
					return null; // multiple symbols found
				}
				if (symbol != null) {
					return null;
				}
				symbol = candidateSymbol2;
			}
			catch (NotFoundException e) {
				// ignore
			}
		}

		if (symbol == null) {
			throw new NotFoundException();
		}

		return symbol;
	}

	private Namespace getNamespace(SymbolPath symbolPath) {
		String parentNs = symbolPath.getParentPath();
		if (parentNs == null) {
			return null;
		}

		List<Namespace> namespaces = NamespaceUtils.getNamespaceByPath(program, null, parentNs);

		if (namespaces.isEmpty()) {
			SymbolTable symbolTable = program.getSymbolTable();
			for (String libraryName : program.getExternalManager().getExternalLibraryNames()) {
				Symbol librarySymbol = symbolTable.getLibrarySymbol(libraryName);
				namespaces = NamespaceUtils.getNamespaceByPath(program,
					(Library) librarySymbol.getObject(), parentNs);
				if (!namespaces.isEmpty()) {
					break; // use first library containing namespace
				}
			}
		}

		if (namespaces.size() > 1) {
			// assume local symbol was specified
			Msg.showError(this, getComponent(), "Invalid Namespace",
				"Invalid namespace specified, expected Class or Namespace");
		}

		return namespaces.isEmpty() ? null : namespaces.get(0);
	}

	/**
	 * Find unique symbol from iterator ignoring related thunks.  
	 * @param symbolIterator symbol iterator
	 * @return unique function or code symbol or null if multiple symbols found
	 * @throws NotFoundException if no symbols were found
	 */
	private Symbol findRefSymbol(Iterator<Symbol> symbolIterator) throws NotFoundException {
		Symbol candidateSymbol = null;
		Symbol candidateThunkSymbol = null;
		Symbol candidateThunkedSymbol = null; // corresponds to candidateThunkSymbol
		while (symbolIterator.hasNext()) {
			Symbol s = symbolIterator.next();
			SymbolType type = s.getSymbolType();
			if (type == SymbolType.FUNCTION || type == SymbolType.LABEL) {
				Symbol thunkedSymbol = getThunkedSymbol(s);
				if (thunkedSymbol != null) {
					// ignore equivalent thunks
					if (candidateThunkSymbol != null &&
						!thunkedSymbol.equals(candidateThunkedSymbol)) {
						return null;
					}
					candidateThunkedSymbol = thunkedSymbol;
					candidateThunkSymbol = s;
				}
				else { // non-thunk symbol
					if (candidateSymbol != null) {
						return null;
					}
					candidateSymbol = s;
				}
			}
		}
		if (candidateSymbol == null) {
			candidateSymbol = candidateThunkSymbol;
		}
		else if (candidateThunkSymbol != null && !candidateSymbol.equals(candidateThunkedSymbol)) {
			return null;
		}
		if (candidateSymbol == null) {
			throw new NotFoundException();
		}
		return candidateSymbol;
	}

	/**
	 * Find unique original external symbol with the given name.  
	 * @param name original external symbol name
	 * @return unique external symbol or null if multiple matching external symbols were found
	 * @throws NotFoundException if no original external symbols were found
	 */
	private Symbol findOriginalExternalSymbol(String name) throws NotFoundException {

		// must examine each external since secondary/original name
		// is not indexed within symbol table
		Symbol candidateSymbol = null;
		SymbolTable symbolTable = program.getSymbolTable();
		ExternalManager externalManager = program.getExternalManager();
		for (Symbol s : symbolTable.getExternalSymbols()) {
			SymbolType type = s.getSymbolType();
			if (type == SymbolType.FUNCTION || type == SymbolType.LABEL) {
				ExternalLocation externalLocation = externalManager.getExternalLocation(s);
				String originalName = externalLocation.getOriginalImportedName();
				if (name.equals(originalName)) {
					if (candidateSymbol != null) {
						return null;
					}
					candidateSymbol = s;
				}
			}
		}
		if (candidateSymbol == null) {
			throw new NotFoundException();
		}
		return candidateSymbol;
	}

	private Symbol getThunkedSymbol(Symbol s) {
		if (s.getSymbolType() != SymbolType.FUNCTION) {
			return null;
		}
		Function f = (Function) s.getObject();
		Function thunkedFunction = f.getThunkedFunction(true);
		return thunkedFunction != null ? thunkedFunction.getSymbol() : null;
	}

	/**
	 * Define the Main panel for the dialog here.
	 */
	private JPanel create() {

		JPanel mainPanel = new JPanel(new PairLayout(5, 5));
		refFunctionField = new JTextField(20);
		mainPanel.add(new GLabel("Destination Function/Address:"));
		mainPanel.add(refFunctionField);

		mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10));

		return mainPanel;
	}

}
