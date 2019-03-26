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
			getNamespaceInfo(tok);
		}
	}

	private void getNamespaceInfo(StringTokenizer tok) {
		String name = tok.nextToken();
		int id = Integer.parseInt(tok.nextToken());
		SymbolType type = SymbolType.getSymbolType(id);
		String sourceName = tok.nextToken();
		SourceType nameSpaceSourceType = SourceType.valueOf(sourceName);
		namespaceInfos.add(new NamespaceInfo(name, type, nameSpaceSourceType));
	}

	public void applyFunctionName(Program program, Function function)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		Address entryPoint = function.getEntryPoint();
		if (entryPoint.isMemoryAddress() && sourceType == SourceType.DEFAULT) {
			// Apply a default name by removing the current one.
			program.getSymbolTable().removeSymbolSpecial(function.getSymbol());
			return;
		}

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace namespace = program.getGlobalNamespace();
		for (NamespaceInfo info : namespaceInfos) {
			Namespace ns = symbolTable.getNamespace(info.name, namespace);
			if (ns != null) {
				if (function.isExternal() != ns.isExternal()) {
					throw new DuplicateNameException("Conflicting namespace: " + info.name);
				}
				if (info.symbolType == SymbolType.CLASS &&
					ns.getSymbol().getSymbolType() == SymbolType.NAMESPACE) {
					// Promote existing namespace to class
					ns = NamespaceUtils.convertNamespaceToClass(ns);
				}
				namespace = ns;
			}
			else {
				namespace = createNamespace(program, info, namespace);
			}
		}

		Symbol s = function.getSymbol();
		s.setNameAndNamespace(symbolName, namespace, sourceType);
	}

	public void addFunctionName(Program program, Function function, boolean isPrimary)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace namespace = program.getGlobalNamespace();
		for (NamespaceInfo info : namespaceInfos) {
			Namespace ns = symbolTable.getNamespace(info.name, namespace);
			namespace = ns != null ? ns : createNamespace(program, info, namespace);
		}
		Symbol functionSymbol = function.getSymbol();
		if (functionSymbol.getSource() == SourceType.DEFAULT) {
			function.getSymbol().setNameAndNamespace(symbolName, namespace, sourceType);
		}
		else {
			// Add a label.
			Symbol addedSymbol = symbolTable.createLabel(function.getEntryPoint(), symbolName,
				namespace, sourceType);
			if (isPrimary && addedSymbol != null) {
				SetLabelPrimaryCmd setLabelPrimaryCmd =
					new SetLabelPrimaryCmd(addedSymbol.getAddress(), addedSymbol.getName(),
						addedSymbol.getParentNamespace());
				setLabelPrimaryCmd.applyTo(program);
			}
		}
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
		String name;
		SymbolType symbolType;
		SourceType sourceType;

		public NamespaceInfo(Namespace namespace) {
			this.name = namespace.getName();
			this.symbolType = namespace.getSymbol().getSymbolType();
			this.sourceType = namespace.getSymbol().getSource();
		}

		public NamespaceInfo(String name, SymbolType type, SourceType sourceType) {
			this.name = name;
			this.symbolType = type;
			this.sourceType = sourceType;
		}

	}

	public String getSymbolName() {
		return symbolName;
	}

	public SourceType getSymbolSourceType() {
		return sourceType;
	}
}
