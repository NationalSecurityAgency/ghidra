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
package ghidra.app.cmd.refs;

import ghidra.framework.cmd.Command;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * Command class for associating a reference with a specific label
 */
public class AssociateSymbolCmd implements Command<Program> {
	private Reference ref;
	private String symbolName;
	private Namespace scope;
	private SymbolTable symTable;
	private String msg = "";

	/**
	 * Constructor.
	 * @param ref the reference to associate with a symbol
	 * @param scope scope that has the symbol to associate with the reference
	 */
	public AssociateSymbolCmd(Reference ref, Namespace scope) {
		this.ref = ref;
		this.scope = scope;
		symbolName = scope.getSymbol().getName();
	}

	/**
	 * Constructor
	 * @param ref the reference to associate with a symbol
	 * @param symbolName the name of the symbol with which to associate the reference.
	 * @param scope scope of the symbol with the given symbolName
	 */
	public AssociateSymbolCmd(Reference ref, String symbolName, Namespace scope) {
		this.ref = ref;
		this.symbolName = symbolName;
		this.scope = scope;
	}

	/**
	 * Create a associate symbol command for a global symbol
	 * @param ref the reference to associate with a symbol
	 * @param symbolName the name of the symbol with which to associate the reference.
	 */
	public AssociateSymbolCmd(Reference ref, String symbolName) {
		this(ref, symbolName, null);
	}

	@Override
	public boolean applyTo(Program program) {
		symTable = program.getSymbolTable();
		ReferenceManager refMgr = program.getReferenceManager();

		Symbol s = symTable.getSymbol(symbolName, ref.getToAddress(), scope);
		if (s == null) {
			msg = "No symbol found for " + symbolName;
			return false;
		}
		refMgr.setAssociation(s, ref);
		return true;
	}

	@Override
	public String getStatusMsg() {
		return msg;
	}

	@Override
	public String getName() {
		return "Set Symbol Reference Association";
	}

}
