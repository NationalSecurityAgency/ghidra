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
package ghidra.trace.database.program;

import java.util.*;

import com.google.common.collect.Iterators;
import com.google.common.collect.Range;

import generic.NestedIterator;
import generic.util.PeekableIterator;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.symbol.*;
import ghidra.trace.model.symbol.*;
import ghidra.util.*;
import ghidra.util.exception.*;

public class DBTraceProgramViewSymbolTable implements SymbolTable {

	protected static class PrimarySymbolIterator extends AbstractPeekableIterator<Symbol>
			implements SymbolIterator {
		private final PeekableIterator<Symbol> it;

		public PrimarySymbolIterator(Iterator<Symbol> it) {
			this.it = PeekableIterators.castOrWrap(it);
		}

		@Override
		public Iterator<Symbol> iterator() {
			return this;
		}

		@Override
		protected Symbol seekNext() {
			if (!it.hasNext()) {
				return null;
			}
			Symbol primary = it.next();
			while (it.hasNext() && primary.getAddress().equals(it.peek().getAddress())) {
				Symbol candidate = it.next();
				if (candidate.isPrimary()) {
					primary = candidate;
					// NOTE: Could return here, but I'll need to advance past
					// everything at this same address on next call, anyway.
				}
			}
			return primary;
		}
	}

	protected final DBTraceProgramView program;
	protected final DBTraceSymbolManager symbolManager;
	protected final DBTraceNamespaceSymbol global;

	public DBTraceProgramViewSymbolTable(DBTraceProgramView program) {
		this.program = program;
		this.symbolManager = program.trace.getSymbolManager();
		this.global = symbolManager.getGlobalNamespace();
	}

	protected TraceNamespaceSymbol assertTraceNamespace(Namespace ns) {
		if (!(ns instanceof TraceNamespaceSymbol)) {
			throw new IllegalArgumentException("Given namespace is not part of this trace");
		}
		return (TraceNamespaceSymbol) ns;
	}

	@Override
	public Symbol createLabel(Address addr, String name, SourceType source)
			throws InvalidInputException {
		return symbolManager.labels().create(program.snap, null, addr, name, global, source);
	}

	@Override
	public Symbol createSymbol(Address addr, String name, SourceType source)
			throws InvalidInputException {
		return createLabel(addr, name, source);
	}

	@Override
	public Symbol createLabel(Address addr, String name, Namespace namespace, SourceType source)
			throws InvalidInputException {
		return symbolManager.labels()
				.create(program.snap, null, addr, name,
					assertTraceNamespace(namespace), source);
	}

	@Override
	public Symbol createSymbol(Address addr, String name, Namespace namespace, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		return createLabel(addr, name, namespace, source);
	}

	@Override
	public boolean removeSymbolSpecial(Symbol sym) {
		// TODO: I'm not sure I understand the point of this method...
		try (LockHold hold = program.trace.lockWrite()) {
			AbstractDBTraceSymbol dbSym = symbolManager.getSymbolByID(sym.getID());
			if (sym != dbSym) {
				throw new IllegalArgumentException("The given symbol is not part of this trace");
			}
			if (dbSym.getSymbolType() != SymbolType.FUNCTION) {
				return dbSym.delete();
			}
			Address address = dbSym.getAddress();
			Collection<? extends TraceLabelSymbol> at =
				symbolManager.labels().getAt(program.snap, null, address, false);
			String name;
			TraceNamespaceSymbol parent;
			SourceType source;
			if (at.isEmpty()) {
				if (dbSym.getSource() == SourceType.DEFAULT) {
					return false; // Can't remove default function symbol
				}
				name = SymbolUtilities.getDefaultFunctionName(address);
				parent = global;
				source = SourceType.DEFAULT;
			}
			else {
				// Absorb another symbol
				TraceLabelSymbol primary = at.iterator().next();
				name = primary.getName();
				parent = primary.getParentNamespace();
				source = primary.getSource();
				// TODO: Notify reference manager of symbol removal?
				// TODO: Should probably do this in delete, not here...
				primary.delete();
			}
			try {
				dbSym.setNameAndNamespace(name, parent, source);
				return true;
			}
			catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
				// TODO: Original catches Exception and returns false. Why?
				throw new AssertionError(e);
			}
		}
	}

	protected <T extends TraceSymbol> T requireVisible(T sym) {
		if (!(sym instanceof TraceSymbolWithLifespan)) {
			return sym;
		}
		if (sym instanceof TraceFunctionSymbol) {
			TraceFunctionSymbol function = (TraceFunctionSymbol) sym;
			return program.isFunctionVisible(function, function.getLifespan()) ? sym : null;
		}
		TraceSymbolWithLifespan wl = (TraceSymbolWithLifespan) sym;
		if (program.viewport.containsAnyUpper(wl.getLifespan())) {
			return sym;
		}
		return null;
	}

	@Override
	public Symbol getSymbol(long symbolID) {
		return requireVisible(symbolManager.getSymbolByID(symbolID));
	}

	@Override
	public Symbol getSymbol(String name, Address addr, Namespace namespace) {
		try (LockHold hold = program.trace.lockRead()) {
			for (TraceSymbol sym : symbolManager.allSymbols()
					.getChildrenNamed(name,
						assertTraceNamespace(namespace))) {
				if (!addr.equals(sym.getAddress())) {
					continue;
				}
				if (requireVisible(sym) == null) {
					continue;
				}
				return sym;
			}
			return null;
		}
	}

	@Override
	public Symbol getGlobalSymbol(String name, Address addr) {
		return getSymbol(name, addr, global);
	}

	@Override
	public Symbol getSymbol(String name, Namespace namespace) {
		try (LockHold hold = program.trace.lockRead()) {
			for (TraceSymbol sym : symbolManager.allSymbols()
					.getChildrenNamed(name,
						assertTraceNamespace(namespace))) {
				if (requireVisible(sym) == null) {
					continue;
				}
				return sym;
			}
			return null;
		}
	}

	@Override
	public Symbol getSymbol(String name) {
		return getSymbol(name, global);
	}

	@Override
	public List<Symbol> getSymbols(String name, Namespace namespace) {
		TraceNamespaceSymbol parent = assertTraceNamespace(namespace);
		try (LockHold hold = program.trace.lockRead()) {
			List<Symbol> result = new ArrayList<>();
			for (TraceSymbol sym : symbolManager.allSymbols().getChildrenNamed(name, parent)) {
				if (requireVisible(sym) != null) {
					result.add(sym);
				}
			}
			return result;
		}
	}

	@Override
	public List<Symbol> getGlobalSymbols(String name) {
		return getSymbols(name, global);
	}

	@Override
	public List<Symbol> getLabelOrFunctionSymbols(String name, Namespace namespace) {
		TraceNamespaceSymbol parent = assertTraceNamespace(namespace);
		try (LockHold hold = program.trace.lockRead()) {
			List<Symbol> result = new ArrayList<>();
			for (TraceSymbol sym : symbolManager.labelsAndFunctions()
					.getChildrenNamed(name,
						parent)) {
				if (requireVisible(sym) != null) {
					result.add(sym);
				}
			}
			return result;
		}
	}

	@Override
	public Symbol getNamespaceSymbol(String name, Namespace namespace) {
		// NOTE: Yes, use namespaces here, not allNamespaces. Not even classes are returned.
		return symbolManager.namespaces().getChildNamed(name, assertTraceNamespace(namespace));
	}

	@Override
	public Symbol getLibrarySymbol(String name) {
		return null;
	}

	@Override
	public Symbol getClassSymbol(String name, Namespace namespace) {
		return symbolManager.classes().getChildNamed(name, assertTraceNamespace(namespace));
	}

	@Override
	public Symbol getParameterSymbol(String name, Namespace namespace) {
		return symbolManager.parameters().getChildNamed(name, assertTraceNamespace(namespace));
	}

	@Override
	public Symbol getLocalVariableSymbol(String name, Namespace namespace) {
		return symbolManager.localVariables().getChildNamed(name, assertTraceNamespace(namespace));
	}

	@Override
	public Symbol getVariableSymbol(String name, Function function) {
		return symbolManager.allVariables().getChildNamed(name, assertTraceNamespace(function));
	}

	@Override
	public Namespace getNamespace(String name, Namespace namespace) {
		return symbolManager.uniqueNamespaces()
				.getChildNamed(name,
					assertTraceNamespace(namespace));
	}

	@Override
	public SymbolIterator getSymbols(String name) {
		return new SymbolIteratorAdapter(symbolManager.allSymbols().getNamed(name).iterator());
	}

	@Override
	public SymbolIterator getAllSymbols(boolean includeDynamicSymbols) {
		return new SymbolIteratorAdapter(
			symbolManager.allSymbols().getAll(includeDynamicSymbols).iterator());
	}

	@Override
	public Symbol getSymbol(Reference ref) {
		return symbolManager.getSymbolByID(ref.getSymbolID());
	}

	@Override
	public Symbol getPrimarySymbol(Address addr) {
		try (LockHold hold = program.trace.lockRead()) {
			Collection<? extends TraceSymbol> at =
				symbolManager.labelsAndFunctions().getAt(program.snap, null, addr, true);
			if (at.isEmpty()) {
				return null;
			}
			return at.iterator().next();
		}
	}

	@Override
	public Symbol[] getSymbols(Address addr) {
		try (LockHold hold = program.trace.lockRead()) {
			Collection<? extends TraceSymbol> at =
				symbolManager.labelsAndFunctions().getAt(program.snap, null, addr, true);
			return at.toArray(new Symbol[at.size()]);
		}
	}

	@Override
	public Symbol[] getUserSymbols(Address addr) {
		try (LockHold hold = program.trace.lockRead()) {
			Collection<? extends TraceSymbol> at =
				symbolManager.labelsAndFunctions().getAt(program.snap, null, addr, false);
			return at.toArray(new Symbol[at.size()]);
		}
	}

	@Override
	public SymbolIterator getSymbols(Namespace namespace) {
		return new SymbolIteratorAdapter(
			symbolManager.allSymbols().getChildren(assertTraceNamespace(namespace)).iterator());
	}

	@Override
	public SymbolIterator getSymbols(long namespaceID) {
		AbstractDBTraceSymbol sym = symbolManager.getSymbolByID(namespaceID);
		if (!(sym instanceof DBTraceNamespaceSymbol)) {
			return new SymbolIteratorAdapter(Collections.emptyIterator());
		}
		DBTraceNamespaceSymbol ns = (DBTraceNamespaceSymbol) sym;
		return new SymbolIteratorAdapter(symbolManager.allSymbols().getChildren(ns).iterator());
	}

	@Override
	public boolean hasSymbol(Address addr) {
		if (addr.isMemoryAddress()) {
			return symbolManager.labelsAndFunctions().hasAt(program.snap, null, addr, true);
		}
		if (addr.getAddressSpace().isRegisterSpace() || addr.isStackAddress()) {
			return symbolManager.allVariables().hasAt(addr, true);
		}
		return false;
	}

	@Override
	public long getDynamicSymbolID(Address addr) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public SymbolIterator getSymbolIterator(String searchStr, boolean caseSensitive) {
		return new SymbolIteratorAdapter(
			symbolManager.allSymbols().getWithMatchingName(searchStr, caseSensitive).iterator());
	}

	@Override
	public SymbolIterator getSymbols(AddressSetView set, SymbolType type, boolean forward) {
		return new SymbolIteratorAdapter(NestedIterator.start(set.iterator(), range -> {
			if (range.getAddressSpace().isMemorySpace()) {
				if (type == SymbolType.LABEL) {
					return symbolManager.labels()
							.getIntersecting(Range.singleton(program.snap),
								null, range, true, forward)
							.iterator();
				}
				if (type == SymbolType.FUNCTION) {
					return symbolManager.functions()
							.getIntersecting(Range.singleton(program.snap),
								null, range, true, forward)
							.iterator();
				}
			}
			if (range.getAddressSpace().isRegisterSpace() ||
				range.getAddressSpace().isStackSpace()) {
				if (type == SymbolType.PARAMETER) {
					return symbolManager.parameters().getIntersecting(range, true).iterator();
				}
				if (type == SymbolType.LOCAL_VAR) {
					return symbolManager.localVariables().getIntersecting(range, true).iterator();
				}
				if (type == SymbolType.GLOBAL_VAR) {
					return symbolManager.globalVariables().getIntersecting(range, true).iterator();
				}
			}
			return Collections.emptyIterator();
		}));
	}

	@Override
	public int getNumSymbols() {
		return symbolManager.allSymbols().size(true);
	}

	protected Iterator<? extends Symbol> getSymbolIteratorAtMySnap(
			TraceSymbolWithLocationView<? extends TraceSymbol> view, AddressSetView asv,
			boolean includeDynamicSymbols, boolean forward) {
		Iterator<AddressRange> rit = asv.iterator(forward);
		Iterator<Iterator<? extends Symbol>> iit = Iterators.transform(rit, range -> {
			return view.getIntersecting(Range.singleton(program.snap), null, range,
				includeDynamicSymbols, forward).iterator();
		});
		return Iterators.concat(iit);
	}

	@Override
	public SymbolIterator getSymbolIterator() {
		return new SymbolIteratorAdapter(getSymbolIteratorAtMySnap(symbolManager.labels(),
			program.language.getAddressFactory().getAddressSet(), true, true));
	}

	@Override
	public SymbolIterator getDefinedSymbols() {
		return new SymbolIteratorAdapter(symbolManager.allSymbols().getAll(false).iterator());
	}

	@Override
	public Symbol getExternalSymbol(String name) {
		return null;
	}

	@Override
	public SymbolIterator getExternalSymbols(String name) {
		return new SymbolIteratorAdapter(Collections.emptyIterator());
	}

	@Override
	public SymbolIterator getExternalSymbols() {
		return new SymbolIteratorAdapter(Collections.emptyIterator());
	}

	@Override
	public SymbolIterator getSymbolIterator(boolean forward) {
		return new SymbolIteratorAdapter(getSymbolIteratorAtMySnap(symbolManager.labels(),
			program.language.getAddressFactory().getAddressSet(), true, forward));
	}

	@Override
	public SymbolIterator getSymbolIterator(Address startAddr, boolean forward) {
		return new SymbolIteratorAdapter(getSymbolIteratorAtMySnap(
			symbolManager.labelsAndFunctions(),
			DBTraceUtils.getAddressSet(program.language.getAddressFactory(), startAddr, forward),
			true, forward));
	}

	@Override
	public SymbolIterator getPrimarySymbolIterator(boolean forward) {
		return new PrimarySymbolIterator(getSymbolIterator(forward));
	}

	@Override
	public SymbolIterator getPrimarySymbolIterator(Address startAddr, boolean forward) {
		return new PrimarySymbolIterator(getSymbolIterator(startAddr, forward));
	}

	@Override
	public SymbolIterator getPrimarySymbolIterator(AddressSetView asv, boolean forward) {
		return new PrimarySymbolIterator(NestedIterator.start(asv.iterator(forward),
			range -> symbolManager.labelsAndFunctions()
					.getIntersecting(
						Range.singleton(program.snap), null, range, true, forward)
					.iterator()));
	}

	@Override
	public void addExternalEntryPoint(Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeExternalEntryPoint(Address addr) {
		// Do nothing
	}

	@Override
	public boolean isExternalEntryPoint(Address addr) {
		return false;
	}

	@Override
	public AddressIterator getExternalEntryPointIterator() {
		return new EmptyAddressIterator();
	}

	@Override
	public LabelHistory[] getLabelHistory(Address addr) {
		return new LabelHistory[] {};
	}

	@Override
	public Iterator<LabelHistory> getLabelHistory() {
		return Collections.emptyIterator();
	}

	@Override
	public boolean hasLabelHistory(Address addr) {
		return false;
	}

	@Override
	public Namespace getNamespace(Address addr) {
		// NOTE: Currently, traces do not allow namespaces to have arbitrary bodies.
		// Instead, their bodies are the union of addresses of their descendants.
		if (addr.isMemoryAddress()) {
			for (TraceSymbol sym : symbolManager.labelsAndFunctions()
					.getAt(program.snap, null,
						addr, true)) {
				if (sym instanceof TraceNamespaceSymbol /* Function */) {
					return (TraceNamespaceSymbol) sym;
				}
				return sym.getParentNamespace();
			}
		}
		if (addr.getAddressSpace().isRegisterSpace() || addr.isStackAddress()) {
			for (TraceSymbol sym : symbolManager.allVariables().getAt(addr, true)) {
				return sym.getParentNamespace();
			}
		}
		return symbolManager.getGlobalNamespace();
	}

	@Override
	public Iterator<GhidraClass> getClassNamespaces() {
		return DBTraceUtils.covariantIterator(symbolManager.classes().getAll(true).iterator());
	}

	@Override
	public GhidraClass createClass(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		return symbolManager.classes().add(name, assertTraceNamespace(parent), source);
	}

	@Override
	public SymbolIterator getChildren(Symbol parentSymbol) {
		if (!(parentSymbol instanceof TraceSymbol)) {
			throw new IllegalArgumentException("Given symbol is not part of this trace");
		}
		if (!(parentSymbol instanceof TraceNamespaceSymbol)) {
			return new SymbolIteratorAdapter(Collections.emptyIterator());
		}
		TraceNamespaceSymbol parent = (TraceNamespaceSymbol) parentSymbol;
		return new SymbolIteratorAdapter(symbolManager.allSymbols().getChildren(parent).iterator());
	}

	@Override
	public Library createExternalLibrary(String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Namespace createNameSpace(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		return symbolManager.namespaces().add(name, assertTraceNamespace(parent), source);
	}

	@Override
	public Namespace getOrCreateNameSpace(Namespace parent, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		try (LockHold hold = program.trace.lockWrite()) {
			Collection<? extends DBTraceNamespaceSymbol> exist =
				symbolManager.namespaces().getNamed(name);
			if (!exist.isEmpty()) {
				return exist.iterator().next();
			}
			return createNameSpace(parent, name, source);
		}
	}

	@Override
	public GhidraClass convertNamespaceToClass(Namespace namespace) {
		if (namespace instanceof GhidraClass) {
			return (GhidraClass) namespace;
		}
		try (LockHold hold = program.trace.lockWrite()) {
			DBTraceNamespaceSymbol dbNamespace = symbolManager.assertIsMine(namespace);

			String origName = dbNamespace.getName();
			SourceType origSource = dbNamespace.getSource();

			String tempName = origName + System.nanoTime();
			DBTraceClassSymbol dbClass =
				symbolManager.classes().add(tempName, dbNamespace.getParentNamespace(), origSource);
			for (AbstractDBTraceSymbol child : dbNamespace.getChildren()) {
				child.setNamespace(dbClass);
			}

			dbNamespace.delete();
			dbClass.setName(origName, origSource);
			return dbClass;
		}
		catch (DuplicateNameException | InvalidInputException | IllegalArgumentException
				| CircularDependencyException e) {
			throw new AssertException("Unexpected exception creating class from namespace", e);
		}
	}

}
