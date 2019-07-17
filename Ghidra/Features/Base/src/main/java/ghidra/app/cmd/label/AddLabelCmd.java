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
package ghidra.app.cmd.label;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

/**
 * Command to add a label.
 */
public class AddLabelCmd implements Command {
	private Address addr;
	private String name;
	private Namespace namespace;
	private boolean useLocalNamespace;
	private SourceType source;
	private String errorMsg = "";
	private Symbol symbol;

	/**
	 * Constructs a new command for adding a label.
	 * @param addr address where the label is to be added.
	 * @param name name of the new label. A null name will cause a default label
	 * be added.
	 * @param namespace the namespace of the label. (i.e. the namespace this label is associated with)
	 * @param source the source of this symbol
	 */
	public AddLabelCmd(Address addr, String name, Namespace namespace, SourceType source) {
		this.addr = addr;
		this.name = name;
		this.namespace = namespace;
		this.source = source;
		useLocalNamespace = false;
	}

	/**
	 * Constructs a new command for adding a label.
	 * @param addr address where the label is to be added.
	 * @param name name of the new label. A null name will cause a default label
	 * be added.
	 * @param useLocalNamespace If true, the namespace will be that of the lowest level namespace
	 * for the indicated address. If false, the global namespace is used for the namespace.
	 * @param source the source of this symbol: Symbol.DEFAULT, Symbol.IMPORTED, Symbol.ANALYSIS, or Symbol.USER_DEFINED.
	 */
	public AddLabelCmd(Address addr, String name, boolean useLocalNamespace, SourceType source) {
		this.addr = addr;
		this.name = name;
		this.useLocalNamespace = useLocalNamespace;
		this.source = source;
	}

	/**
	 * Constructs a new command for adding a label.
	 * @param addr address where the label is to be added.
	 * @param name name of the new label. A null name will cause a default label be added.
	 * @param source the source of this symbol
	 */
	public AddLabelCmd(Address addr, String name, SourceType source) {
		this(addr, name, null, source);
	}

	/**
	 *
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		SymbolTable st = ((Program) obj).getSymbolTable();
		if (namespace == null && useLocalNamespace) {
			namespace = st.getNamespace(addr);
		}
		try {
			symbol = st.createLabel(addr, name, namespace, source);
			return true;
		}
		catch (InvalidInputException e) {
			if ((name == null) || (name.length() == 0)) {
				errorMsg = "You must enter a valid label name";
			}
			else {
				errorMsg = "Invalid name: " + e.getMessage();
			}
		}

		return false;

	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return errorMsg;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Add Label";
	}

	public String getLabelName() {
		return name;
	}

	public Address getLabelAddr() {
		return addr;
	}

	public void setLabelAddr(Address addr) {
		this.addr = addr;
	}

	public void setLabelName(String name) {
		this.name = name;
	}

	public void setNamespace(Namespace namespace) {
		this.namespace = namespace;
	}

	public Symbol getSymbol() {
		return symbol;
	}
}
