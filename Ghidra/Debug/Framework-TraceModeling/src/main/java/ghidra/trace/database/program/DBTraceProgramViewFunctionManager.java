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

import static ghidra.lifecycle.Unfinished.TODO;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import com.google.common.collect.Range;

import generic.NestedIterator;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.symbol.*;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.symbol.TraceFunctionSymbol;
import ghidra.trace.util.EmptyFunctionIterator;
import ghidra.trace.util.WrappingFunctionIterator;
import ghidra.util.LockHold;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DBTraceProgramViewFunctionManager implements FunctionManager {

	protected final DBTraceProgramView program;
	protected final DBTraceFunctionSymbolView functions;
	protected final DBTraceNamespaceSymbol global;

	public DBTraceProgramViewFunctionManager(DBTraceProgramView program) {
		this.program = program;
		this.functions = program.trace.getSymbolManager().functions();
		this.global = program.trace.getSymbolManager().getGlobalNamespace();
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public FunctionTagManager getFunctionTagManager() {
		return TODO();
	}

	@Override
	public List<String> getCallingConventionNames() {
		return functions.getCallingConventionNames();
	}

	@Override
	public PrototypeModel getDefaultCallingConvention() {
		return functions.getDefaultCallingConvention();
	}

	@Override
	public PrototypeModel getCallingConvention(String name) {
		return functions.getCallingConvention(name);
	}

	@Override
	public PrototypeModel[] getCallingConventions() {
		return functions.getCallingConventions();
	}

	@Override
	public TraceFunctionSymbol createFunction(String name, Address entryPoint, AddressSetView body,
			SourceType source) throws InvalidInputException, OverlappingFunctionException {
		return functions.create(program.snap, entryPoint, body, name, null, global, source);
	}

	protected static DBTraceNamespaceSymbol validateParent(Namespace nameSpace) {
		if (!(nameSpace instanceof DBTraceNamespaceSymbol)) {
			throw new IllegalArgumentException("Given namespace is not part of this trace");
		}
		return (DBTraceNamespaceSymbol) nameSpace;
	}

	protected static DBTraceFunctionSymbol validateThunked(Function thunked) {
		if (!(thunked instanceof DBTraceFunctionSymbol)) {
			throw new IllegalArgumentException("Given thunked function is not part of this trace");
		}
		return (DBTraceFunctionSymbol) thunked;
	}

	@Override
	public TraceFunctionSymbol createFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, SourceType source)
			throws InvalidInputException, OverlappingFunctionException {
		return functions.create(program.snap, entryPoint, body, name, null,
			validateParent(nameSpace), source);
	}

	@Override
	public TraceFunctionSymbol createThunkFunction(String name, Namespace nameSpace,
			Address entryPoint, AddressSetView body, Function thunkedFunction, SourceType source)
			throws OverlappingFunctionException {
		try {
			return functions.create(program.snap, entryPoint, body, name,
				validateThunked(thunkedFunction), validateParent(nameSpace), source);
		}
		catch (InvalidInputException e) {
			// TODO: Why not just declare this as thrown???
			throw new RuntimeException("Unexpected for default named function", e);
		}
	}

	@Override
	public int getFunctionCount() {
		return functions.size(false); // NOTE: May include those not at this snap
	}

	@Override
	public boolean removeFunction(Address entryPoint) {
		try (LockHold hold = program.trace.lockWrite()) {
			TraceFunctionSymbol at = getFunctionAt(entryPoint);
			if (at == null) {
				return false;
			}
			at.delete();
			return true;
		}
	}

	@Override
	public TraceFunctionSymbol getFunctionAt(Address entryPoint) {
		if (!entryPoint.getAddressSpace().isMemorySpace()) {
			return null;
		}

		for (long s : program.viewport.getOrderedSnaps()) {
			// NOTE: There ought only to be one, since no overlaps allowed.
			for (TraceFunctionSymbol at : functions.getAt(s, null, entryPoint, false)) {
				if (entryPoint.equals(at.getEntryPoint())) {
					return at;
				}
				else {
					return null; // Anything below is occluded by the found function
				}
			}
		}
		return null;
	}

	@Override
	public TraceFunctionSymbol getReferencedFunction(Address address) {
		if (!address.getAddressSpace().isMemorySpace()) {
			return null;
		}
		TraceFunctionSymbol found = getFunctionAt(address);
		if (found != null) {
			return found;
		}
		TraceData data =
			program.getTopCode(address, (space, s) -> space.data().getContaining(s, address));
		if (data == null) {
			return null;
		}
		DBTraceReference ref = program.trace.getReferenceManager()
				.getPrimaryReferenceFrom(data.getStartSnap(), address, 0);
		return ref == null ? null : getFunctionAt(ref.getToAddress());
	}

	@Override
	public TraceFunctionSymbol getFunctionContaining(Address addr) {
		// NOTE: There ought only to be one, since no overlaps allowed.
		for (TraceFunctionSymbol at : functions.getAt(program.snap, null, addr, false)) {
			return at;
		}
		return null;
	}

	protected Iterator<? extends DBTraceFunctionSymbol> getFunctionsInRange(AddressRange range,
			boolean forward) {
		return functions.getIntersecting(Range.singleton(program.snap), null, range, false,
			forward).iterator();
	}

	@Override
	public FunctionIterator getFunctions(boolean forward) {
		return getFunctions(program.getAddressFactory().getAddressSet(), forward);
	}

	@Override
	public FunctionIterator getFunctions(Address start, boolean forward) {
		return getFunctions(DBTraceUtils.getAddressSet(program.getAddressFactory(), start, forward),
			forward);
	}

	@Override
	public FunctionIterator getFunctions(AddressSetView asv, boolean forward) {
		return new WrappingFunctionIterator(
			NestedIterator.start(asv.iterator(forward), rng -> getFunctionsInRange(rng, forward)),
			f -> {
				if (!asv.contains(f.getEntryPoint())) {
					return false;
				}
				return true;
			});
	}

	@Override
	public FunctionIterator getFunctionsNoStubs(boolean forward) {
		return getFunctionsNoStubs(program.getAddressFactory().getAddressSet(), forward);
	}

	@Override
	public FunctionIterator getFunctionsNoStubs(Address start, boolean forward) {
		return getFunctionsNoStubs(
			DBTraceUtils.getAddressSet(program.getAddressFactory(), start, forward), forward);
	}

	@Override
	public FunctionIterator getFunctionsNoStubs(AddressSetView asv, boolean forward) {
		return new WrappingFunctionIterator(
			NestedIterator.start(asv.iterator(forward), rng -> getFunctionsInRange(rng, forward)),
			f -> {
				if (f.isThunk()) {
					return false;
				}
				if (!asv.contains(f.getEntryPoint())) {
					return false;
				}
				if (program.trace.getCodeManager()
						.instructions()
						.getAt(program.snap,
							f.getEntryPoint()) == null) {
					return false;
				}
				return true;
			});
	}

	@Override
	public FunctionIterator getExternalFunctions() {
		return EmptyFunctionIterator.INSTANCE;
	}

	@Override
	public boolean isInFunction(Address addr) {
		// TODO: Could use idMap directly to avoid loading the function
		return getFunctionContaining(addr) != null;
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		Iterator<? extends DBTraceFunctionSymbol> it =
			getFunctionsInRange(new AddressRangeImpl(startAddr, endAddr), true);
		while (it.hasNext()) {
			monitor.checkCanceled();
			it.next().delete();
		}
	}

	@Override
	public void setProgram(ProgramDB program) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void invalidateCache(boolean all) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<Function> getFunctionsOverlapping(AddressSetView set) {
		return new WrappingFunctionIterator(
			NestedIterator.start(set.iterator(true), rng -> getFunctionsInRange(rng, true)));
	}

	@Override
	public Variable getReferencedVariable(Address instrAddr, Address storageAddr, int size,
			boolean isRead) {
		TraceFunctionSymbol function = getFunctionContaining(instrAddr);
		if (function == null) {
			return null;
		}
		return DBTraceFunctionSymbolView.getReferencedVariable(function, instrAddr, storageAddr,
			size, isRead, program.language);
	}

	@Override
	public TraceFunctionSymbol getFunction(long key) {
		return functions.getByKey(key);
	}
}
