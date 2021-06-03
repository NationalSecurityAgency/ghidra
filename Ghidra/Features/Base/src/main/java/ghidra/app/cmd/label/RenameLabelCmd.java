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
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Command for renaming labels. Handles converting back and forth between
 * default and named labels as well.
 */
public class RenameLabelCmd implements Command {

	private Address addr;
	private String oldName;
	private String newName;
	private Namespace currentNamespace;
	private Namespace newNamespace;
	private SourceType source;

	private String errorMsg = "";

	/**
	 * Constructs a new command for renaming a label within a specified namespace.
	 * @param addr Address of label to be renamed.
	 * @param oldName the current name of the label to be renamed.
	 * @param newName the new name for the label. (null for default)
	 * @param currentNamespace the symbol's current name space. (The namespace to associate this label with)
	 * @param source the source of this symbol
	 */
	public RenameLabelCmd(Address addr, String oldName, String newName, Namespace currentNamespace,
			SourceType source) {
		this.addr = addr;
		this.oldName = oldName;
		this.newName = newName;
		this.currentNamespace = currentNamespace;
		this.newNamespace = currentNamespace;
		this.source = source;
	}

	/**
	 * Constructs a new command for renaming a label within currentNamespace and changing the
	 * namespace to newNamespace.
	 * @param addr Address of label to be renamed.
	 * @param oldName the current name of the label to be renamed.
	 * @param newName the new name for the label. (null for default)
	 * @param currentNamespace the symbol's current parent name space (null indicates global namespace)
	 * @param newNamespace final namespace (null indicates global namespace)
	 * @param source the source of this symbol
	 */
	public RenameLabelCmd(Address addr, String oldName, String newName, Namespace currentNamespace,
			Namespace newNamespace, SourceType source) {
		this(addr, oldName, newName, currentNamespace, source);
		this.newNamespace = newNamespace;
	}

	/**
	 * Constructs a new command for renaming global labels.
	 * @param addr Address of label to be renamed.
	 * @param oldName the name of the label to be renamed; may be null
	 * of the existing label is a dynamic label
	 * @param newName the new name for the label
	 * @param source the source of this symbol
	 */
	public RenameLabelCmd(Address addr, String oldName, String newName, SourceType source) {
		this(addr, oldName, newName, null, source);
	}

	/**
	 *
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		Program program = (Program) obj;
		if (currentNamespace == null) {
			currentNamespace = program.getGlobalNamespace();
		}

		if (newNamespace == null) {
			newNamespace = program.getGlobalNamespace();
		}

		SymbolTable st = ((Program) obj).getSymbolTable();
		Symbol s = null;
		if (oldName == null) {
			s = st.getPrimarySymbol(addr);
		}
		else {
			s = st.getSymbol(oldName, addr, currentNamespace);
		}

		if (s == null) {
			errorMsg = "Symbol not found: " + oldName;
			return false;
		}

		try {
			if (!currentNamespace.equals(newNamespace)) {
				s.setNameAndNamespace(newName, newNamespace, source);
			}
			else {
				s.setName(newName, source);

				if (newName.length() == 0 && s.getSource() != SourceType.DEFAULT) {
					errorMsg = "Rename failed - cannot set non-default symbol name to \"\"";
					return false;
				}

				if (!newName.equals(s.getName())) {
					errorMsg = "Rename failed";
					return false;
				}
			}
			return true;
		}
		catch (DuplicateNameException e) {
			errorMsg = "Symbol already exists: " + newName;
		}
		catch (InvalidInputException e) {
			errorMsg = "Invalid entry: " + e.getMessage();
		}
		catch (CircularDependencyException e) {
			errorMsg = e.getMessage();
		}
		return false;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Rename Label";
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return errorMsg;
	}

}
