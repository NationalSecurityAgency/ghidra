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
package ghidra.feature.vt.api.stringable;

import java.util.*;

import generic.json.Json;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.NamespaceUtils;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class FunctionNameStringable extends Stringable {

	public static final String SHORT_NAME = "FUN_SYM";

	private String symbolName;
	private SourceType sourceType;
	private List<NamespaceInfo> namespaceInfos = new ArrayList<>();

	public FunctionNameStringable() {
		this(null);
	}

	public FunctionNameStringable(Symbol symbol) {
		super(SHORT_NAME);
		if (symbol == null) {
			return;
		}

		this.symbolName = symbol.getName();
		this.sourceType = symbol.getSource();

		Namespace namespace = symbol.getParentNamespace();
		while (namespace != null) {
			if (namespace instanceof GlobalNamespace) {
				break;
			}
			namespaceInfos.add(new NamespaceInfo(namespace));
			namespace = namespace.getParentNamespace();
		}
		Collections.reverse(namespaceInfos);
	}

	@Override
	public String getDisplayString() {
		return symbolName;
	}

	@Override
	protected String doConvertToString(Program program) {
		StringBuilder builder = new StringBuilder();
		builder.append(symbolName).append(DELIMITER);
		builder.append(sourceType.name()).append(DELIMITER);
		for (NamespaceInfo info : namespaceInfos) {
			builder.append(info.name).append(DELIMITER);
			builder.append(info.symbolType.getID()).append(DELIMITER);
			builder.append(info.sourceType.name()).append(DELIMITER);
		}
		return builder.toString();
	}

	@Override
	protected void doRestoreFromString(String string, Program program) {
		StringTokenizer tok = new StringTokenizer(string, DELIMITER);
		symbolName = tok.nextToken();
		String sourceName = tok.nextToken();
		sourceType = SourceType.valueOf(sourceName);

		while (tok.hasMoreTokens()) {
			addNamespaceInfo(tok);
		}
	}

	private void addNamespaceInfo(StringTokenizer tok) {
		String name = tok.nextToken();
		int id = Integer.parseInt(tok.nextToken());
		SymbolType type = SymbolType.getSymbolType(id);
		String sourceName = tok.nextToken();
		SourceType nameSpaceSourceType = SourceType.valueOf(sourceName);
		namespaceInfos.add(new NamespaceInfo(name, type, nameSpaceSourceType));
	}

	// Note: this is only meant to be called on the 'destination stringable'
	public void unapplyFunctionNameAndNamespace(Function targetFunction)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		Namespace ns = createAllNamespacesAndClasses(targetFunction, namespaceInfos);
		doApplyFunctionName(targetFunction, ns);
	}

	// Note: this is only meant to be called on the 'source stringable'
	public void applyFunctionNameAndNamespace(Function targetFunction)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		// use this stringable's namespace info to create the equivalent namespace in the target
		Namespace ns = createAllNamespacesAndClasses(targetFunction, namespaceInfos);

		if (ns instanceof GlobalNamespace) {
			Namespace targetNs = targetFunction.getParentNamespace();
			if (!(targetNs instanceof GlobalNamespace)) {
				// Assume for now that any non-global namespace in the target is preferred by the
				// user to the default global namespace.  We can always add another option for this
				// behavior in the future.  If we change this code, then update the help.
				ns = targetNs;
			}
		}

		doApplyFunctionName(targetFunction, ns);
	}

	// Note: this is only meant to be called on the 'source stringable'
	public void applyFunctionName(Function targetFunction)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		// apply only the name; keep the existing namespace
		Symbol s = targetFunction.getSymbol();
		Namespace ns = s.getParentNamespace();
		doApplyFunctionName(targetFunction, ns);
	}

	private void doApplyFunctionName(Function targetFunction, Namespace namespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		Symbol s = targetFunction.getSymbol();
		Program targetProgram = targetFunction.getProgram();
		SymbolTable symbolTable = targetProgram.getSymbolTable();
		Address entryPoint = targetFunction.getEntryPoint();
		if (entryPoint.isMemoryAddress() && sourceType == SourceType.DEFAULT) {
			// Apply a default name by removing the current one.
			symbolTable.removeSymbolSpecial(targetFunction.getSymbol());
			s.setNamespace(namespace);
			return;
		}

		s.setNameAndNamespace(symbolName, namespace, sourceType);
	}

	private Namespace createAllNamespacesAndClasses(Function destFunction,
			List<NamespaceInfo> infos) throws DuplicateNameException, InvalidInputException {

		Program destProgram = destFunction.getProgram();
		SymbolTable symbolTable = destProgram.getSymbolTable();
		Namespace namespace = destProgram.getGlobalNamespace();
		for (NamespaceInfo info : infos) {
			Namespace ns = symbolTable.getNamespace(info.name, namespace);
			if (ns == null) {
				namespace = createNamespace(destProgram, info, namespace);
				continue;
			}

			if (destFunction.isExternal() != ns.isExternal()) {
				throw new DuplicateNameException("Conflicting namespace: " + info.name);
			}
			if (info.symbolType == SymbolType.CLASS &&
				ns.getSymbol().getSymbolType() == SymbolType.NAMESPACE) {
				// Promote existing namespace to class
				ns = NamespaceUtils.convertNamespaceToClass(ns);
			}
			namespace = ns;
		}

		return namespace;
	}

	public void addFunctionNameAndNamespace(Function sourceFunction,
			Function destFunction, boolean isPrimary)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		List<NamespaceInfo> infos = new ArrayList<>();
		Namespace namespace = sourceFunction.getParentNamespace();
		while (namespace != null) {
			if (namespace instanceof GlobalNamespace) {
				break;
			}
			infos.add(new NamespaceInfo(namespace));
			namespace = namespace.getParentNamespace();
		}
		Collections.reverse(infos);

		doAddFunctionName(destFunction, infos, isPrimary);
	}

	public void addFunctionName(Function destFunction, boolean isPrimary)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		doAddFunctionName(destFunction, List.of(), isPrimary);
	}

	private void doAddFunctionName(Function destFunction, List<NamespaceInfo> namespaces,
			boolean isPrimary)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		Program destProgram = destFunction.getProgram();
		SymbolTable symbolTable = destProgram.getSymbolTable();
		Namespace namespace = createAllNamespaces(destProgram, namespaces);
		Symbol symbol = destFunction.getSymbol();
		if (symbol.getSource() == SourceType.DEFAULT) {
			// Special case: when the destination is default, replace the default symbol instead of
			// adding a new symbol.
			applyFunctionName(destFunction);
			return;
		}

		Address entryPoint = destFunction.getEntryPoint();
		Symbol addedSymbol = symbolTable.createLabel(entryPoint, symbolName, namespace, sourceType);
		if (!isPrimary || addedSymbol == null) {
			return;
		}

		Address address = addedSymbol.getAddress();
		String name = addedSymbol.getName();
		Namespace ns = addedSymbol.getParentNamespace();
		SetLabelPrimaryCmd cmd = new SetLabelPrimaryCmd(address, name, ns);
		cmd.applyTo(destProgram);
	}

	public String getSymbolNamespace() {
		if (namespaceInfos.isEmpty()) {
			return null;
		}

		StringBuilder buffy = new StringBuilder();
		for (NamespaceInfo info : namespaceInfos) {
			buffy.append(info.name).append(Namespace.DELIMITER);
		}

		int end = buffy.length();
		int n = Namespace.DELIMITER.length();
		buffy.delete(end - n, end);
		return buffy.toString();
	}

	public String getSymbolName() {
		return getSymbolName(false);
	}

	public String getSymbolName(boolean includeNamespace) {
		if (!includeNamespace) {
			return symbolName;
		}

		StringBuilder buffy = new StringBuilder();
		for (NamespaceInfo info : namespaceInfos) {
			buffy.append(info.name).append(Namespace.DELIMITER);
		}
		buffy.append(symbolName);
		return buffy.toString();
	}

	public SourceType getSymbolSourceType() {
		return sourceType;
	}

	private Namespace createAllNamespaces(Program program, List<NamespaceInfo> namespaces)
			throws DuplicateNameException, InvalidInputException {

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace namespace = program.getGlobalNamespace();
		for (NamespaceInfo info : namespaces) {
			Namespace nextNs = symbolTable.getNamespace(info.name, namespace);
			namespace = nextNs != null ? nextNs : createNamespace(program, info, namespace);
		}
		return namespace;
	}

	private Namespace createNamespace(Program program, NamespaceInfo info, Namespace namespace)
			throws DuplicateNameException, InvalidInputException {
		SymbolTable symbolTable = program.getSymbolTable();
		String name = info.name;
		SymbolType type = info.symbolType;
		SourceType namespaceSourceType = info.sourceType;

		if (type == SymbolType.LIBRARY) {
			return symbolTable.createExternalLibrary(name, namespaceSourceType);
		}
		else if (type == SymbolType.CLASS) {
			return symbolTable.createClass(namespace, name, namespaceSourceType);
		}
		return symbolTable.createNameSpace(namespace, name, namespaceSourceType);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((sourceType == null) ? 0 : sourceType.hashCode());
		result = prime * result + ((symbolName == null) ? 0 : symbolName.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || (getClass() != obj.getClass())) {
			return false;
		}
		FunctionNameStringable other = (FunctionNameStringable) obj;

		if (!SystemUtilities.isEqual(symbolName, other.symbolName)) {
			return false;
		}
		if (sourceType != other.sourceType) {
			return false;
		}
		if (namespaceInfos.size() != other.namespaceInfos.size()) {
			return false;
		}
		for (int i = 0; i < namespaceInfos.size(); i++) {
			if (!namespaceInfos.get(i).equals(other.namespaceInfos.get(i))) {
				return false;
			}
		}
		return true;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private static class NamespaceInfo {

		private String name;
		private SymbolType symbolType;
		private SourceType sourceType;

		NamespaceInfo(Namespace namespace) {
			this.name = namespace.getName();
			this.symbolType = namespace.getSymbol().getSymbolType();
			this.sourceType = namespace.getSymbol().getSource();
		}

		NamespaceInfo(String name, SymbolType type, SourceType sourceType) {
			this.name = name;
			this.symbolType = type;
			this.sourceType = sourceType;
		}

		@Override
		public String toString() {
			return Json.toString(this);
		}

		@Override
		public int hashCode() {
			return Objects.hash(name, sourceType, symbolType);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			NamespaceInfo other = (NamespaceInfo) obj;
			return Objects.equals(name, other.name) && sourceType == other.sourceType &&
				Objects.equals(symbolType, other.symbolType);
		}

	}
}
