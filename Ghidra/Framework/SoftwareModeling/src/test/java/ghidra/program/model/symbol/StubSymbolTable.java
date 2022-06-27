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
package ghidra.program.model.symbol;

import java.util.Iterator;
import java.util.List;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class StubSymbolTable implements SymbolTable {

	@Override
	public Symbol createLabel(Address addr, String name, SourceType source)
			throws InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol createLabel(Address addr, String name, Namespace namespace, SourceType source)
			throws InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeSymbolSpecial(Symbol sym) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getSymbol(long symbolID) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getSymbol(String name, Address addr, Namespace namespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getGlobalSymbol(String name, Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<Symbol> getGlobalSymbols(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<Symbol> getLabelOrFunctionSymbols(String name, Namespace namespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getNamespaceSymbol(String name, Namespace namespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getLibrarySymbol(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getClassSymbol(String name, Namespace namespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getParameterSymbol(String name, Namespace namespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getLocalVariableSymbol(String name, Namespace namespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<Symbol> getSymbols(String name, Namespace namespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getVariableSymbol(String name, Function function) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Namespace getNamespace(String name, Namespace namespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getSymbols(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getAllSymbols(boolean includeDynamicSymbols) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getSymbol(Reference ref) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getPrimarySymbol(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol[] getSymbols(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getSymbolsAsIterator(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol[] getUserSymbols(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getSymbols(Namespace namespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getSymbols(long namespaceID) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasSymbol(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getDynamicSymbolID(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getSymbolIterator(String searchStr, boolean caseSensitive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getSymbols(AddressSetView set, SymbolType type, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getNumSymbols() {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getSymbolIterator() {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getDefinedSymbols() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getExternalSymbol(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getExternalSymbols(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getExternalSymbols() {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getSymbolIterator(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getSymbolIterator(Address startAddr, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getPrimarySymbolIterator(boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getPrimarySymbolIterator(Address startAddr, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getPrimarySymbolIterator(AddressSetView asv, boolean forward) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addExternalEntryPoint(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeExternalEntryPoint(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isExternalEntryPoint(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressIterator getExternalEntryPointIterator() {
		throw new UnsupportedOperationException();
	}

	@Override
	public LabelHistory[] getLabelHistory(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<LabelHistory> getLabelHistory() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasLabelHistory(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Namespace getNamespace(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<GhidraClass> getClassNamespaces() {
		throw new UnsupportedOperationException();
	}

	@Override
	public GhidraClass createClass(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolIterator getChildren(Symbol parentSymbol) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Library createExternalLibrary(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Namespace createNameSpace(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public GhidraClass convertNamespaceToClass(Namespace namespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Namespace getOrCreateNameSpace(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

}
