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

import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class MultipleSymbolStringable extends Stringable {

	public static final String SHORT_NAME = "MULTI_SYM";

	private ArrayList<SymbolInfo> symbolInfos;

	public MultipleSymbolStringable() {
		this((List<Symbol>) null); // deserialization constructor
	}

	public MultipleSymbolStringable(Symbol[] symbols) {
		this(Arrays.asList(symbols));
	}

	public MultipleSymbolStringable(List<Symbol> symbols) {
		super(SHORT_NAME);
		symbolInfos = new ArrayList<>();
		if (symbols == null) {
			return;
		}
		int count = symbols.size();
		for (int index = 0; index < count; index++) {
			Symbol symbol = symbols.get(index);
			symbolInfos.add(new SymbolInfo(symbol));
		}
	}

	@Override
	public String getDisplayString() {
		StringBuilder buildy = new StringBuilder();
		for (SymbolInfo symbolInfo : symbolInfos) {
			buildy.append(symbolInfo.getDisplayString()).append('\n');
		}
		return buildy.toString();
	}

	public String[] getNames() {
		String[] names = new String[symbolInfos.size()];
		int i = 0;
		for (SymbolInfo symbolInfo : symbolInfos) {
			names[i++] = symbolInfo.getName();
		}
		return names;
	}

	public boolean contains(Symbol symbol) {
		SymbolInfo symbolInfo = new SymbolInfo(symbol);
		for (SymbolInfo currentSymbolInfo : symbolInfos) {
			if (symbolInfo.equals(currentSymbolInfo)) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected String doConvertToString(Program program) {
		if (symbolInfos == null || symbolInfos.size() == 0) {
			return "";
		}

		StringBuilder buildy = new StringBuilder();
		for (SymbolInfo symbolInfo : symbolInfos) {
			symbolInfo.convertToString(buildy);
			buildy.append(DOUBLE_DELIMITER);
		}
		return buildy.toString();
	}

	@Override
	protected void doRestoreFromString(String string, Program program) {
		StringTokenizer tokenizer = new StringTokenizer(string, DOUBLE_DELIMITER);
		while (tokenizer.hasMoreTokens()) {
			symbolInfos.add(new SymbolInfo(tokenizer.nextToken()));
		}
	}

	public List<Symbol> setSymbols(Program program, Address address, boolean setAsPrimary)
			throws DuplicateNameException, InvalidInputException {
		// remove unneeded symbols

		// Add any symbols not already there.
		SymbolTable symbolTable = program.getSymbolTable();
		List<Symbol> symbols = new ArrayList<>();
		for (SymbolInfo symbolInfo : symbolInfos) {
			if (symbolInfo.isDynamic) {
				continue;
			}
			String name = symbolInfo.symbolName;
			SourceType sourceType = symbolInfo.sourceType;
			Namespace namespace = getNamespaceForNewLabel(program, symbolInfo, address);
			Symbol symbol = symbolTable.getSymbol(name, address, namespace);
			if (symbol != null) {
				if (symbol.getSource() != sourceType) {
					symbol.setSource(sourceType);
				}
				symbols.add(symbol);
			}
			else {
				// Add the symbol.
				symbol = createSymbol(program, address, symbolInfo);
				symbols.add(symbol);
			}
			if (setAsPrimary) {
				symbol.setPrimary(); // Don't want to change function symbol, so don't use command.

				// Only set the first symbol as primary.
				setAsPrimary = false;
			}
		}
		return symbols;
	}

	private Symbol createSymbol(Program program, Address address, SymbolInfo symbolInfo)
			throws DuplicateNameException, InvalidInputException {
		Namespace namespace = getNamespaceForNewLabel(program, symbolInfo, address);
		return program.getSymbolTable().createLabel(address, symbolInfo.getName(), namespace,
			symbolInfo.sourceType);
	}

	private Namespace getNamespaceForNewLabel(Program program, SymbolInfo symbolInfo,
			Address address) throws DuplicateNameException, InvalidInputException {

		if (symbolInfo.isNamespaceFunctionBased) {
			Function f = program.getFunctionManager().getFunctionContaining(address);
			if (f != null) {
				return f;
			}
		}

		// otherwise create or get the path of namespaces.
		Namespace namespace = program.getGlobalNamespace();
		for (NamespaceInfo info : symbolInfo.namespaceInfos) {
			namespace = getOrCreateNamespace(program, info, namespace);
		}
		return namespace;
	}

	private Namespace getOrCreateNamespace(Program program, NamespaceInfo info, Namespace parent)
			throws DuplicateNameException, InvalidInputException {
		Namespace namespace = program.getSymbolTable().getNamespace(info.name, parent);
		if (namespace != null) {
			return namespace;
		}
		return createNamespace(program, info, parent);
	}

	private Namespace createNamespace(Program program, NamespaceInfo info, Namespace namespace)
			throws DuplicateNameException, InvalidInputException {
		SymbolTable symbolTable = program.getSymbolTable();
		String name = info.name;
		SymbolType type = info.symbolType;
		SourceType sourceType = info.sourceType;

		if (type == SymbolType.LIBRARY) {
			return symbolTable.createExternalLibrary(name, sourceType);
		}
		else if (type == SymbolType.CLASS) {
			return symbolTable.createClass(namespace, name, sourceType);
		}
		return symbolTable.createNameSpace(namespace, name, sourceType);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if ((obj == null) || (getClass() != obj.getClass())) {
			return false;
		}
		MultipleSymbolStringable other = (MultipleSymbolStringable) obj;
		int count = symbolInfos.size();
		int otherCount = other.symbolInfos.size();
		if (count != otherCount) {
			return false;
		}

		return symbolInfos.equals(other.symbolInfos);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((symbolInfos == null) ? 0 : symbolInfos.hashCode());
		return result;
	}

	public boolean isEmpty() {
		return symbolInfos.isEmpty();
	}

	public boolean containsDynamic() {
		for (SymbolInfo info : symbolInfos) {
			if (SymbolUtilities.isDynamicSymbolPattern(info.getName(), true)) {
				return true;
			}
		}
		return false;
	}

	public boolean isAllDynamic() {
		for (SymbolInfo info : symbolInfos) {
			if (!SymbolUtilities.isDynamicSymbolPattern(info.getName(), true)) {
				return false;
			}
		}
		return true;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private class NamespaceInfo {
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

	private class SymbolInfo {
		private final String symbolName;
		private final SourceType sourceType;
		private final boolean isDynamic;
		private final List<NamespaceInfo> namespaceInfos = new ArrayList<>();
		private boolean isNamespaceFunctionBased;

		SymbolInfo(Symbol symbol) {
			this.symbolName = symbol.getName();
			this.sourceType = symbol.getSource();
			this.isDynamic = symbol.isDynamic();
			Namespace namespace = symbol.getParentNamespace();
			while (namespace != null) {
				if (namespace instanceof Function) {
					isNamespaceFunctionBased = true;
					break;
				}
				if (namespace instanceof GlobalNamespace) {
					break;
				}
				namespaceInfos.add(new NamespaceInfo(namespace));
				namespace = namespace.getParentNamespace();
			}
			Collections.reverse(namespaceInfos);
		}

		SymbolInfo(String string) {
			StringTokenizer tok = new StringTokenizer(string, DELIMITER);
			symbolName = tok.nextToken();
			String sourceName = tok.nextToken();
			sourceType = SourceType.valueOf(sourceName);
			isDynamic = Boolean.parseBoolean(tok.nextToken());

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

		void convertToString(StringBuilder builder) {
			builder.append(symbolName).append(DELIMITER);
			builder.append(sourceType.name()).append(DELIMITER);
			builder.append(Boolean.toString(isDynamic)).append(DELIMITER);
			for (NamespaceInfo info : namespaceInfos) {
				builder.append(info.name).append(DELIMITER);
				builder.append(info.symbolType.getID()).append(DELIMITER);
				builder.append(info.sourceType.name()).append(DELIMITER);
			}
		}

		String getName() {
			return symbolName;
		}

		String getDisplayString() {
			return symbolName;
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
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			SymbolInfo other = (SymbolInfo) obj;
			if (!SystemUtilities.isEqual(sourceType, other.sourceType)) {
				return false;
			}
			if (!SystemUtilities.isEqual(symbolName, other.symbolName)) {
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
	}
}
