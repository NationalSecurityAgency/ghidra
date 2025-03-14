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
package ghidra.features.base.replace.items;

import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.symboltree.SymbolTreeService;
import ghidra.features.base.quickfix.QuickFixStatus;
import ghidra.features.base.replace.RenameQuickFix;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * QuickFix for renaming symbols (labels, functions, namespaces, classes, parameters, or 
 * local variables).
 */
public class RenameSymbolQuickFix extends RenameQuickFix {

	private Symbol symbol;

	/**
	 * Constructor
	 * @param symbol the symbol to be renamed
	 * @param newName the new name for the symbol
	 */
	public RenameSymbolQuickFix(Symbol symbol, String newName) {
		super(symbol.getProgram(), symbol.getName(), newName);
		this.symbol = symbol;
		performDuplicateCheck();
	}

	@Override
	public String getItemType() {
		return symbol.getSymbolType().toString();
	}

	private void performDuplicateCheck() {
		Namespace parentNamespace = symbol.getParentNamespace();
		SymbolTable symbolTable = program.getSymbolTable();
		List<Symbol> symbols = symbolTable.getSymbols(replacement, parentNamespace);
		if (!symbols.isEmpty()) {
			setStatus(QuickFixStatus.WARNING,
				"There is already a symbol named \"" + replacement +
					"\" in namespace \"" + parentNamespace.getName() + "\"");
		}
	}

	@Override
	public Address getAddress() {
		Address address = symbol.getAddress();
		if (address == Address.NO_ADDRESS) {
			address = null;
		}
		return address;
	}

	@Override
	public void statusChanged(QuickFixStatus newStatus) {
		if (newStatus == QuickFixStatus.NONE) {
			performDuplicateCheck();
		}
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return symbol.getProgramLocation();
	}

	@Override
	public String getPath() {
		Namespace namespace = symbol.getParentNamespace();
		return namespace.getName(true);
	}

	@Override
	public String doGetCurrent() {
		if (symbol.isDeleted()) {
			return null;
		}
		return symbol.getName();
	}

	@Override
	public void execute() {
		try {
			symbol.setName(replacement, SourceType.USER_DEFINED);
		}
		catch (DuplicateNameException | InvalidInputException e) {
			setStatus(QuickFixStatus.ERROR, "Rename Failed! " + e.getMessage());
		}
	}

	@Override
	public Map<String, String> getCustomToolTipData() {
		SymbolType symbolType = symbol.getSymbolType();
		Namespace parentNamespace = symbol.getParentNamespace();
		if (symbolType == SymbolType.PARAMETER || symbolType == SymbolType.LOCAL_VAR) {
			return Map.of("Function", parentNamespace.getName(true));
		}
		return Map.of("Namespace", parentNamespace.getName(false));
	}

	@Override
	protected boolean navigateSpecial(ServiceProvider services, boolean fromSelectionChange) {
		if (symbol.getAddress().isMemoryAddress()) {
			return false; 		// let default navigation handle it
		}

		// This is a symbol that can't be shown in the listing, so directly request the
		// symbol tree to select this symbol
		SymbolTreeService service = services.getService(SymbolTreeService.class);
		if (service != null) {
			service.selectSymbol(symbol);
			return true;
		}
		return false;
	}
}
