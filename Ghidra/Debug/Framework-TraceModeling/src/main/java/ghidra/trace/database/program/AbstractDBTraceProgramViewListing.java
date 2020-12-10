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

import com.google.common.collect.Range;

import generic.NestedIterator;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.util.PropertyMap;
import ghidra.trace.database.memory.DBTraceMemoryRegion;
import ghidra.trace.database.symbol.DBTraceFunctionSymbol;
import ghidra.trace.model.Trace;
import ghidra.trace.model.listing.TraceCodeOperations;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.map.TracePropertyMap;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.program.TraceProgramViewListing;
import ghidra.trace.model.symbol.TraceFunctionSymbol;
import ghidra.util.IntersectionAddressSetView;
import ghidra.util.LockHold;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractDBTraceProgramViewListing implements TraceProgramViewListing {
	public static final String[] EMPTY_STRING_ARRAY = new String[] {};
	public static final String TREE_NAME = "Trace Tree";

	protected static class WrappingCodeUnitIterator implements CodeUnitIterator {
		protected final Iterator<? extends CodeUnit> it;

		public WrappingCodeUnitIterator(Iterator<? extends CodeUnit> it) {
			this.it = it;
		}

		@Override
		public Iterator<CodeUnit> iterator() {
			return this;
		}

		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		@Override
		public CodeUnit next() {
			return it.next();
		}
	}

	protected static class WrappingInstructionIterator implements InstructionIterator {
		protected final Iterator<? extends Instruction> it;

		public WrappingInstructionIterator(Iterator<? extends Instruction> it) {
			this.it = it;
		}

		@Override
		public Iterator<Instruction> iterator() {
			return this;
		}

		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		@Override
		public Instruction next() {
			return it.next();
		}
	}

	protected static class WrappingDataIterator implements DataIterator {
		protected final Iterator<? extends Data> it;

		public WrappingDataIterator(Iterator<? extends Data> it) {
			this.it = it;
		}

		@Override
		public Iterator<Data> iterator() {
			return this;
		}

		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		@Override
		public Data next() {
			return it.next();
		}
	}

	protected final DBTraceProgramView program;
	protected final TraceCodeOperations codeOperations;

	protected final DBTraceProgramViewRootModule rootModule;
	protected final Map<DBTraceMemoryRegion, DBTraceProgramViewFragment> fragmentsByRegion =
		new HashMap<>();

	public AbstractDBTraceProgramViewListing(DBTraceProgramView program,
			TraceCodeOperations codeOperations) {
		this.program = program;
		this.codeOperations = codeOperations;

		this.rootModule = new DBTraceProgramViewRootModule(this);
	}

	@Override
	public TraceProgramView getProgram() {
		return program;
	}

	@Override
	public Trace getTrace() {
		return program.trace;
	}

	@Override
	public long getSnap() {
		return program.snap;
	}

	@Override
	public CodeUnit getCodeUnitAt(Address addr) {
		return codeOperations.codeUnits().getAt(program.snap, addr);
	}

	@Override
	public CodeUnit getCodeUnitContaining(Address addr) {
		return codeOperations.codeUnits().getContaining(program.snap, addr);
	}

	@Override
	public CodeUnit getCodeUnitAfter(Address addr) {
		return codeOperations.codeUnits().getAfter(program.snap, addr);
	}

	@Override
	public CodeUnit getCodeUnitBefore(Address addr) {
		return codeOperations.codeUnits().getBefore(program.snap, addr);
	}

	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, boolean forward) {
		// HACK
		if (CodeUnit.INSTRUCTION_PROPERTY.equals(property)) {
			return new WrappingCodeUnitIterator(
				codeOperations.instructions().get(program.snap, forward).iterator());
		}
		// TODO: Other "special" property types

		// TODO: Cover this in testing
		TracePropertyMap<?> map =
			program.trace.getAddressPropertyManager().getPropertyMap(property);
		if (map == null) {
			return new WrappingCodeUnitIterator(Collections.emptyIterator());
		}
		return new WrappingCodeUnitIterator(NestedIterator.start(
			map.getAddressSetView(Range.singleton(program.snap)).iterator(forward),
			rng -> program.trace.getCodeManager()
					.codeUnits()
					.get(program.snap, rng, forward)
					.iterator()));
	}

	protected static AddressRange fixRange(AddressRange range, Address start, boolean forward) {
		if (!range.contains(start)) {
			return range;
		}
		return forward ? new AddressRangeImpl(start, range.getMaxAddress())
				: new AddressRangeImpl(range.getMinAddress(), start);
	}

	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, Address addr, boolean forward) {
		// HACK
		if (CodeUnit.INSTRUCTION_PROPERTY.equals(property)) {
			return new WrappingCodeUnitIterator(
				codeOperations.instructions().get(program.snap, addr, forward).iterator());
		}
		// TODO: Other "special" property types

		// TODO: Cover this in testing
		TracePropertyMap<?> map =
			program.trace.getAddressPropertyManager().getPropertyMap(property);
		if (map == null) {
			return new WrappingCodeUnitIterator(Collections.emptyIterator());
		}
		return new WrappingCodeUnitIterator(NestedIterator.start(
			map.getAddressSetView(Range.singleton(program.snap)).iterator(addr, forward),
			rng -> program.trace.getCodeManager()
					.codeUnits()
					.get(program.snap, fixRange(rng, addr, forward), forward)
					.iterator()));
	}

	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, AddressSetView addrSet,
			boolean forward) {
		// HACK
		if (CodeUnit.INSTRUCTION_PROPERTY.equals(property)) {
			return new WrappingCodeUnitIterator(
				codeOperations.instructions().get(program.snap, addrSet, forward).iterator());
		}
		// TODO: Other "special" property types

		// TODO: Cover this in testing
		TracePropertyMap<?> map =
			program.trace.getAddressPropertyManager().getPropertyMap(property);
		if (map == null) {
			return new WrappingCodeUnitIterator(Collections.emptyIterator());
		}
		return new WrappingCodeUnitIterator(NestedIterator.start(
			new IntersectionAddressSetView(map.getAddressSetView(Range.singleton(program.snap)),
				addrSet).iterator(forward),
			rng -> program.trace.getCodeManager()
					.codeUnits()
					.get(program.snap, rng, forward)
					.iterator()));
	}

	@Override
	public CodeUnitIterator getCommentCodeUnitIterator(int commentType, AddressSetView addrSet) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AddressIterator getCommentAddressIterator(int commentType, AddressSetView addrSet,
			boolean forward) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AddressIterator getCommentAddressIterator(AddressSetView addrSet, boolean forward) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getComment(int commentType, Address address) {
		return program.trace.getCommentAdapter().getComment(program.snap, address, commentType);
	}

	@Override
	public void setComment(Address address, int commentType, String comment) {
		program.trace.getCommentAdapter()
				.setComment(Range.atLeast(program.snap), address,
					commentType, comment);
	}

	@Override
	public CodeUnitIterator getCodeUnits(boolean forward) {
		return new WrappingCodeUnitIterator(
			codeOperations.codeUnits().get(program.snap, forward).iterator());
	}

	@Override
	public CodeUnitIterator getCodeUnits(Address start, boolean forward) {
		return new WrappingCodeUnitIterator(
			codeOperations.codeUnits().get(program.snap, start, forward).iterator());
	}

	@Override
	public CodeUnitIterator getCodeUnits(AddressSetView addressSet, boolean forward) {
		return new WrappingCodeUnitIterator(
			codeOperations.codeUnits().get(program.snap, addressSet, forward).iterator());
	}

	@Override
	public Instruction getInstructionAt(Address addr) {
		return codeOperations.instructions().getAt(program.snap, addr);
	}

	@Override
	public Instruction getInstructionContaining(Address addr) {
		return codeOperations.instructions().getContaining(program.snap, addr);
	}

	@Override
	public Instruction getInstructionAfter(Address addr) {
		return codeOperations.instructions().getAfter(program.snap, addr);
	}

	@Override
	public Instruction getInstructionBefore(Address addr) {
		return codeOperations.instructions().getBefore(program.snap, addr);
	}

	@Override
	public InstructionIterator getInstructions(boolean forward) {
		return new WrappingInstructionIterator(
			codeOperations.instructions().get(program.snap, forward).iterator());
	}

	@Override
	public InstructionIterator getInstructions(Address start, boolean forward) {
		return new WrappingInstructionIterator(
			codeOperations.instructions().get(program.snap, start, forward).iterator());
	}

	@Override
	public InstructionIterator getInstructions(AddressSetView addressSet, boolean forward) {
		return new WrappingInstructionIterator(
			codeOperations.instructions().get(program.snap, addressSet, forward).iterator());
	}

	@Override
	public Data getDataAt(Address addr) {
		return codeOperations.data().getAt(program.snap, addr);
	}

	@Override
	public Data getDataContaining(Address addr) {
		return codeOperations.data().getContaining(program.snap, addr);
	}

	@Override
	public Data getDataAfter(Address addr) {
		return codeOperations.data().getAfter(program.snap, addr);
	}

	@Override
	public Data getDataBefore(Address addr) {
		return codeOperations.data().getBefore(program.snap, addr);
	}

	@Override
	public DataIterator getData(boolean forward) {
		return new WrappingDataIterator(
			codeOperations.data().get(program.snap, forward).iterator());
	}

	@Override
	public DataIterator getData(Address start, boolean forward) {
		return new WrappingDataIterator(
			codeOperations.data().get(program.snap, start, forward).iterator());
	}

	@Override
	public DataIterator getData(AddressSetView addressSet, boolean forward) {
		return new WrappingDataIterator(
			codeOperations.data().get(program.snap, addressSet, forward).iterator());
	}

	@Override
	public Data getDefinedDataAt(Address addr) {
		return codeOperations.definedData().getAt(program.snap, addr);
	}

	@Override
	public Data getDefinedDataContaining(Address addr) {
		return codeOperations.definedData().getContaining(program.snap, addr);
	}

	@Override
	public Data getDefinedDataAfter(Address addr) {
		return codeOperations.definedData().getAfter(program.snap, addr);
	}

	@Override
	public Data getDefinedDataBefore(Address addr) {
		return codeOperations.definedData().getBefore(program.snap, addr);
	}

	@Override
	public DataIterator getDefinedData(boolean forward) {
		return new WrappingDataIterator(
			codeOperations.definedData().get(program.snap, forward).iterator());
	}

	@Override
	public DataIterator getDefinedData(Address start, boolean forward) {
		return new WrappingDataIterator(
			codeOperations.definedData().get(program.snap, start, forward).iterator());
	}

	@Override
	public DataIterator getDefinedData(AddressSetView addressSet, boolean forward) {
		return new WrappingDataIterator(
			codeOperations.definedData().get(program.snap, addressSet, forward).iterator());
	}

	@Override
	public Data getUndefinedDataAt(Address addr) {
		return codeOperations.undefinedData().getAt(program.snap, addr);
	}

	@Override
	public Data getUndefinedDataAfter(Address addr, TaskMonitor monitor) {
		return codeOperations.undefinedData().getAfter(program.snap, addr);
	}

	@Override
	public Data getUndefinedDataBefore(Address addr, TaskMonitor monitor) {
		return codeOperations.undefinedData().getBefore(program.snap, addr);
	}

	@Override
	public Data getFirstUndefinedData(AddressSetView addressSet, TaskMonitor monitor) {
		try (LockHold hold = program.trace.lockRead()) {
			for (TraceData u : codeOperations.undefinedData().get(program.snap, addressSet, true)) {
				return u;
			}
			return null;
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote This could technically use a (lazy) view; however, to be consistent with
	 *           expectations established by {@link ProgramDB}, it constructs the actual set, and
	 *           permits cancellation by the monitor.
	 */
	@Override
	public AddressSet getUndefinedRanges(AddressSetView set, boolean initializedMemoryOnly,
			TaskMonitor monitor) throws CancelledException {
		AddressSet result = new AddressSet();
		for (AddressRange range : set) {
			for (AddressRange und : codeOperations.undefinedData()
					.getAddressSetView(program.snap, range)) {
				monitor.checkCanceled();
				result.add(und.intersect(range));
			}
		}
		return result;
	}

	@Override
	public CodeUnit getDefinedCodeUnitAfter(Address addr) {
		return codeOperations.definedUnits().getAfter(program.snap, addr);
	}

	@Override
	public CodeUnit getDefinedCodeUnitBefore(Address addr) {
		return codeOperations.definedUnits().getBefore(program.snap, addr);
	}

	@Override
	public DataIterator getCompositeData(boolean forward) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public DataIterator getCompositeData(Address start, boolean forward) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public DataIterator getCompositeData(AddressSetView addrSet, boolean forward) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Iterator<String> getUserDefinedProperties() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void removeUserDefinedProperty(String propertyName) {
		// TODO Auto-generated method stub

	}

	@Override
	public PropertyMap getPropertyMap(String propertyName) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Instruction createInstruction(Address addr, InstructionPrototype prototype,
			MemBuffer memBuf, ProcessorContextView context) throws CodeUnitInsertionException {
		// TODO: Why memBuf? Can it vary from program memory?
		try (LockHold hold = program.trace.lockWrite()) {
			return codeOperations.instructions()
					.create(Range.atLeast(program.snap), addr,
						prototype, context);
		}
	}

	@Override
	public AddressSetView addInstructions(InstructionSet instructionSet, boolean overwrite)
			throws CodeUnitInsertionException {
		return codeOperations.instructions()
				.addInstructionSet(Range.atLeast(program.snap),
					instructionSet, overwrite);
	}

	@Override
	public Data createData(Address addr, DataType dataType, int length)
			throws CodeUnitInsertionException {
		return codeOperations.definedData()
				.create(Range.atLeast(program.snap), addr, dataType,
					length);
	}

	@Override
	public Data createData(Address addr, DataType dataType) throws CodeUnitInsertionException {
		return codeOperations.definedData().create(Range.atLeast(program.snap), addr, dataType);
	}

	@Override
	public void clearCodeUnits(Address startAddr, Address endAddr, boolean clearContext) {
		try {
			clearCodeUnits(startAddr, endAddr, clearContext, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public void clearComments(Address startAddr, Address endAddr) {
		program.trace.getCommentAdapter()
				.clearComments(Range.atLeast(program.snap),
					new AddressRangeImpl(startAddr, endAddr), CodeUnit.NO_COMMENT);
	}

	@Override
	public void clearProperties(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		// TODO Auto-generated method stub

	}

	@Override
	public ProgramFragment getFragment(String treeName, Address addr) {
		DBTraceMemoryRegion region =
			program.trace.getMemoryManager().getRegionContaining(program.snap, addr);
		if (region == null) {
			return null;
		}
		return fragmentsByRegion.computeIfAbsent(region,
			r -> new DBTraceProgramViewFragment(this, r));
	}

	@Override
	public ProgramModule getModule(String treeName, String name) {
		if (TREE_NAME.equals(treeName) && TREE_NAME.equals(name)) {
			return rootModule;
		}
		return null;
	}

	@Override
	public ProgramFragment getFragment(String treeName, String name) {
		DBTraceMemoryRegion region =
			program.trace.getMemoryManager().getLiveRegionByPath(program.snap, name);
		if (region == null) {
			return null;
		}
		return fragmentsByRegion.computeIfAbsent(region,
			r -> new DBTraceProgramViewFragment(this, r));
	}

	@Override
	public ProgramModule createRootModule(String treeName) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramModule getRootModule(String treeName) {
		if (TREE_NAME.equals(treeName)) {
			return rootModule;
		}
		return null;
	}

	@Override
	public ProgramModule getRootModule(long treeID) {
		if (treeID == 0) {
			return rootModule;
		}
		return null;
	}

	@Override
	public ProgramModule getDefaultRootModule() {
		return rootModule;
	}

	@Override
	public String[] getTreeNames() {
		// TODO: Implement program trees?
		//return new String[] { TREE_NAME };
		return new String[] {};
	}

	@Override
	public boolean removeTree(String treeName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void renameTree(String oldName, String newName) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getNumCodeUnits() {
		// TODO: Even with R-Trees, counting requires traversal of at least the included entries
		// TODO: If needed, implement the "dual-rectangle" variant.
		// From a search, it seems nothing relies on this thing's accuracy.
		return codeOperations.definedUnits().size();
	}

	@Override
	public long getNumDefinedData() {
		return codeOperations.definedData().size();
		// TODO: See getNumCodeUnits
	}

	@Override
	public long getNumInstructions() {
		// TODO: See getNumCodeUnits
		return Long.MAX_VALUE;
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		return program.getDataTypeManager();
	}

	@Override
	public TraceFunctionSymbol createFunction(String name, Address entryPoint, AddressSetView body,
			SourceType source) throws InvalidInputException, OverlappingFunctionException {
		return program.functionManager.createFunction(name, entryPoint, body, source);
	}

	@Override
	public TraceFunctionSymbol createFunction(String name, Namespace nameSpace, Address entryPoint,
			AddressSetView body, SourceType source)
			throws InvalidInputException, OverlappingFunctionException {
		return program.functionManager.createFunction(name, nameSpace, entryPoint, body, source);
	}

	@Override
	public void removeFunction(Address entryPoint) {
		program.functionManager.removeFunction(entryPoint);
	}

	@Override
	public Function getFunctionAt(Address entryPoint) {
		return program.functionManager.getFunctionAt(entryPoint);
	}

	@Override
	public List<Function> getGlobalFunctions(String name) {
		return new ArrayList<>(program.trace.getSymbolManager().functions().getGlobalsNamed(name));
	}

	@Override
	public List<Function> getFunctions(String namespace, String name) {
		// NOTE: This implementation allows namespaces to contain the separator symbol
		List<Function> result = new ArrayList<>();
		for (DBTraceFunctionSymbol func : program.trace.getSymbolManager()
				.functions()
				.getNamed(
					name)) {
			if (namespace.equals(func.getParentNamespace().getName(true))) {
				result.add(func);
			}
		}
		return result;
	}

	@Override
	public Function getFunctionContaining(Address addr) {
		return program.functionManager.getFunctionContaining(addr);
	}

	@Override
	public FunctionIterator getExternalFunctions() {
		return program.functionManager.getExternalFunctions();
	}

	@Override
	public FunctionIterator getFunctions(boolean forward) {
		return program.functionManager.getFunctions(forward);
	}

	@Override
	public FunctionIterator getFunctions(Address start, boolean forward) {
		return program.functionManager.getFunctions(start, forward);
	}

	@Override
	public FunctionIterator getFunctions(AddressSetView asv, boolean forward) {
		return program.functionManager.getFunctions(asv, forward);
	}

	@Override
	public boolean isInFunction(Address addr) {
		return program.functionManager.isInFunction(addr);
	}

	@Override
	public CommentHistory[] getCommentHistory(Address addr, int commentType) {
		return new CommentHistory[] {};
	}
}
