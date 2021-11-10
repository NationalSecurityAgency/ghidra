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

import java.util.Objects;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Command for renaming labels. Handles converting back and forth between default and named labels 
 * as well.
 */
public class RenameLabelCmd implements Command {

	private Address addr;
	private String oldName;
	private String newName;
	private Symbol existingSymbol;
	private Namespace currentNamespace;
	private Namespace newNamespace;
	private SourceType source;

	private String errorMessage = "";

	/**
	 * Constructs a new command for renaming <B>global</B> labels.
	 * 
	 * @param addr Address of label to be renamed
	 * @param oldName the name of the label to be renamed; may be null if the existing label is a 
	 * dynamic label
	 * @param newName the new name for the label
	 * @param source the source of this symbol
	 */
	public RenameLabelCmd(Address addr, String oldName, String newName, SourceType source) {
		this(addr, oldName, newName, null, null, source);
	}

	/**
	 * Constructor renaming an existing symbol, but not changing its namespace 
	 * 
	 * @param symbol the existing symbol; may not be null
	 * @param newName the new symbol name
	 * @param source the desired symbol source
	 */
	public RenameLabelCmd(Symbol symbol, String newName, SourceType source) {
		this(symbol, newName, symbol.getParentNamespace(), source);
	}

	/**
	 * Constructor renaming an existing symbol and changing its namespace.  If you do not need
	 * to change the namespace, then call {@link #RenameLabelCmd(Symbol, String, SourceType)}.
	 * 
	 * @param symbol the existing symbol; may not be null
	 * @param newName the new symbol name
	 * @param newNamespace the new symbol namespace
	 * @param source the desired symbol source
	 */
	public RenameLabelCmd(Symbol symbol, String newName, Namespace newNamespace,
			SourceType source) {

		this.existingSymbol = Objects.requireNonNull(symbol);
		this.addr = symbol.getAddress();
		this.oldName = symbol.getName();
		this.newName = newName;
		this.currentNamespace = symbol.getParentNamespace();
		this.newNamespace = newNamespace;
		this.source = source;
	}

	/**
	 * Constructs a new command for renaming a label within currentNamespace and changing the
	 * namespace to newNamespace.
	 * 
	 * @param addr Address of label to be renamed
	 * @param oldName the current name of the label to be renamed
	 * @param newName the new name for the label. (null for default)
	 * @param currentNamespace the symbol's current parent name space; null for global namespace
	 * @param newNamespace the desired namespace; null for global namespace
	 * @param source the source of this symbol
	 */
	private RenameLabelCmd(Address addr, String oldName, String newName, Namespace currentNamespace,
			Namespace newNamespace, SourceType source) {
		this.addr = addr;
		this.oldName = oldName;
		this.newName = newName;
		this.currentNamespace = currentNamespace;
		this.newNamespace = newNamespace;
		this.source = source;
	}

	@Override
	public String getName() {
		return "Rename Label";
	}

	@Override
	public String getStatusMsg() {
		return errorMessage;
	}

	@Override
	public boolean applyTo(DomainObject obj) {

		Program program = (Program) obj;
		if (currentNamespace == null) {
			currentNamespace = program.getGlobalNamespace();
		}
		if (newNamespace == null) {
			newNamespace = program.getGlobalNamespace();
		}

		if (!parseNameAndNamespace(program, newNamespace, newName)) {
			return false; // errorMessage already set
		}

		Symbol s = getSymbol(program);
		if (s == null) {
			return false; // errorMessage already set
		}

		if (StringUtils.isBlank(newName) && s.getSource() != SourceType.DEFAULT) {
			errorMessage = "Cannot set non-default symbol name to \"\"";
			return false;
		}

		try {
			if (!currentNamespace.equals(newNamespace)) {
				s.setNameAndNamespace(newName, newNamespace, source);
			}
			else {
				s.setName(newName, source);
				if (!newName.equals(s.getName())) {
					errorMessage = "Rename failed";
					return false;
				}
			}
			return true;
		}
		catch (DuplicateNameException e) {
			errorMessage = "Symbol already exists: " + newName;
		}
		catch (InvalidInputException e) {
			errorMessage = "Invalid entry: " + e.getMessage();
		}
		catch (CircularDependencyException e) {
			errorMessage = e.getMessage();
		}
		return false;
	}

	private boolean parseNameAndNamespace(Program program, Namespace rootNamespace, String name) {

		SymbolPath symbolPath = getSymbolPath(name);
		if (symbolPath == null) {
			return false; // invalid symbol name
		}

		// see if the user specified a namespace path 
		Namespace parent = getOrCreateNamespaces(program, symbolPath, rootNamespace);
		if (parent == null) {
			return false; // create namespace failed
		}

		// update the new namespace and symbol name to reflect the parse results
		newNamespace = parent;
		newName = symbolPath.getName();
		return true;
	}

	private Symbol getSymbol(Program program) {

		if (existingSymbol != null) {
			return existingSymbol;
		}

		SymbolTable st = program.getSymbolTable();
		Symbol s = null;
		if (oldName != null) {
			s = st.getSymbol(oldName, addr, currentNamespace);
		}
		else {
			s = st.getPrimarySymbol(addr);
			if (s != null && !s.isDynamic()) {
				// noted by the constructor, a null name can only be used to rename dynamic symbols
				errorMessage = "Must specify name of symbol to be renamed";
				return null;
			}
		}

		if (s == null) {
			errorMessage = "Symbol not found: " + oldName;
			return null;
		}
		return s;
	}

	// note: the root namespace will be used as the parent for any namespaces found in 'symbolPath'
	private Namespace getOrCreateNamespaces(Program program, SymbolPath symbolPath,
			Namespace rootNamespace) {
		SymbolPath parentPath = symbolPath.getParent();
		if (parentPath == null) {
			return rootNamespace;
		}

		//
		// Prefer a non-function namespace.  This allows us to put a function inside of a namespace
		// sharing the same name.
		//
		SymbolPath fullPath = new SymbolPath(rootNamespace.getSymbol()).append(parentPath);
		Namespace nonFunctionNs = NamespaceUtils.getNonFunctionNamespace(program, fullPath);
		if (nonFunctionNs != null) {
			return nonFunctionNs;
		}

		//
		// At this point we can either reuse an existing function namespace or we have to create
		// a new non-function namespaces, depending upon the names being used.  Only use an
		// existing function as a namespace if none of namespace path entries match the function
		// name.
		//
		String name = symbolPath.getName();
		if (!parentPath.containsPathEntry(name)) {
			Namespace functionNamespace =
				NamespaceUtils.getFunctionNamespaceContaining(program, parentPath, addr);
			if (functionNamespace != null) {
				return functionNamespace;
			}
		}

		CreateNamespacesCmd cmd =
			new CreateNamespacesCmd(parentPath.getPath(), rootNamespace, SourceType.USER_DEFINED);
		if (cmd.applyTo(program)) {
			return cmd.getNamespace();
		}

		errorMessage = cmd.getStatusMsg();
		return null;
	}

	private SymbolPath getSymbolPath(String symbolName) {

		if (StringUtils.isBlank(symbolName)) {
			errorMessage = "Name cannot be blank";
			return null;
		}

		return new SymbolPath(symbolName);
	}
}
