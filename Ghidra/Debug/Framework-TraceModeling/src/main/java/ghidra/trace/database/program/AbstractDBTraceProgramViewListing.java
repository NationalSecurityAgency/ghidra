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

import java.nio.ByteBuffer;
import java.util.*;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalNotification;
import com.google.common.collect.Iterators;
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
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.listing.UndefinedDBTraceData;
import ghidra.trace.database.memory.DBTraceMemoryRegion;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.database.symbol.DBTraceFunctionSymbol;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.*;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.map.TracePropertyMap;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.program.TraceProgramViewListing;
import ghidra.trace.model.symbol.TraceFunctionSymbol;
import ghidra.trace.util.*;
import ghidra.util.*;
import ghidra.util.AddressIteratorAdapter;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractDBTraceProgramViewListing implements TraceProgramViewListing {
	public static final String[] EMPTY_STRING_ARRAY = new String[] {};
	public static final String TREE_NAME = "Trace Tree";

	protected class DBTraceProgramViewUndefinedData extends UndefinedDBTraceData {
		public DBTraceProgramViewUndefinedData(DBTrace trace, long snap, Address address,
				DBTraceThread thread, int frameLevel) {
			super(trace, snap, address, thread, frameLevel);
		}

		@Override
		public int getBytes(ByteBuffer buffer, int addressOffset) {
			DBTraceMemorySpace mem = trace.getMemoryManager().get(this, false);
			if (mem == null) {
				// TODO: 0-fill instead? Will need to check memory space bounds.
			}
			return mem.getViewBytes(program.snap, address.add(addressOffset), buffer);
		}
	}

	protected final DBTraceProgramView program;
	protected final TraceCodeOperations codeOperations;

	protected final DBTraceProgramViewRootModule rootModule;
	protected final Map<DBTraceMemoryRegion, DBTraceProgramViewFragment> fragmentsByRegion =
		new HashMap<>();

	protected final Map<AddressSnap, UndefinedDBTraceData> undefinedCache =
		CacheBuilder.newBuilder()
				.removalListener(
					this::undefinedRemovedFromCache)
				.weakValues()
				.build()
				.asMap();

	public AbstractDBTraceProgramViewListing(DBTraceProgramView program,
			TraceCodeOperations codeOperations) {
		this.program = program;
		this.codeOperations = codeOperations;

		this.rootModule = new DBTraceProgramViewRootModule(this);
	}

	private void undefinedRemovedFromCache(
			RemovalNotification<AddressSnap, UndefinedDBTraceData> rn) {
		// Do nothing
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

	protected <T extends TraceCodeUnit> T getTopCode(
			java.util.function.Function<Long, T> codeFunc) {
		return program.viewport.getTop(s -> {
			T cu = codeFunc.apply(s);
			if (cu != null && program.isCodeVisible(cu, cu.getLifespan())) {
				return cu;
			}
			return null;
		});
	}

	protected TraceCodeUnit orUndef(TraceCodeUnit cu, Address address) {
		if (cu != null) {
			return cu;
		}
		return doCreateUndefinedUnit(address);
	}

	protected TraceData orUndefData(TraceData data, Address address) {
		return (TraceData) orUndef(data, address);
	}

	protected TraceData reqUndef(TraceCodeUnit cu, Address address) {
		if (cu != null) {
			return null;
		}
		return doCreateUndefinedUnit(address);
	}

	protected <T> T next(Iterator<T> it) {
		if (it.hasNext()) {
			return it.next();
		}
		return null;
	}

	protected Comparator<CodeUnit> getUnitComparator(boolean forward) {
		return forward
				? (u1, u2) -> u1.getMinAddress().compareTo(u2.getMinAddress())
				: (u1, u2) -> -u1.getMinAddress().compareTo(u2.getMinAddress());
	}

	protected <T extends TraceCodeUnit> Iterator<T> getTopCodeIterator(
			java.util.function.Function<Long, Iterator<T>> iterFunc, boolean forward) {
		return Iterators.filter(
			program.viewport.mergedIterator(iterFunc, getUnitComparator(forward)),
			cu -> program.isCodeVisible(cu, cu.getLifespan()));
	}

	protected AddressSet getAddressSet(Address start, boolean forward) {
		AddressFactory factory = program.getAddressFactory();
		AddressSet all = program.allAddresses;
		return forward
				? factory.getAddressSet(start, all.getMaxAddress())
				: factory.getAddressSet(all.getMinAddress(), start);
	}

	protected UndefinedDBTraceData doCreateUndefinedUnit(Address address) {
		return undefinedCache.computeIfAbsent(new DefaultAddressSnap(address, program.snap),
			ot -> new DBTraceProgramViewUndefinedData(program.trace, program.snap, address, null,
				0));
	}

	protected Iterator<? extends TraceInstruction> getInstructionIterator(Address start,
			boolean forward) {
		return getTopCodeIterator(
			s -> codeOperations.instructions().get(s, start, forward).iterator(), forward);
	}

	protected Iterator<? extends TraceInstruction> getInstructionIterator(AddressSetView set,
			boolean forward) {
		return getTopCodeIterator(
			s -> codeOperations.instructions().get(s, set, forward).iterator(), forward);
	}

	protected Iterator<? extends TraceInstruction> getInstructionIterator(boolean forward) {
		return getTopCodeIterator(
			s -> codeOperations.instructions().get(s, forward).iterator(), forward);
	}

	protected Iterator<? extends TraceData> getDefinedDataIterator(Address start, boolean forward) {
		return getTopCodeIterator(
			s -> codeOperations.definedData().get(s, start, forward).iterator(), forward);
	}

	protected Iterator<? extends TraceData> getDefinedDataIterator(AddressSetView set,
			boolean forward) {
		return getTopCodeIterator(
			s -> codeOperations.definedData().get(s, set, forward).iterator(), forward);
	}

	protected Iterator<? extends TraceData> getDefinedDataIterator(boolean forward) {
		return getTopCodeIterator(
			s -> codeOperations.definedData().get(s, forward).iterator(), forward);
	}

	protected Iterator<? extends TraceCodeUnit> getDefinedUnitIterator(Address start,
			boolean forward) {
		return getTopCodeIterator(
			s -> codeOperations.definedUnits().get(s, start, forward).iterator(), forward);
	}

	protected Iterator<? extends TraceCodeUnit> getDefinedUnitIterator(AddressSetView set,
			boolean forward) {
		return getTopCodeIterator(
			s -> codeOperations.definedUnits().get(s, set, forward).iterator(), forward);
	}

	protected Iterator<TraceData> getUndefinedDataIterator(Address start, boolean forward) {
		AddressSet set = getAddressSet(start, forward);
		Address defStart = start;
		if (forward) {
			CodeUnit defUnit =
				getTopCode(s -> codeOperations.definedUnits().getContaining(s, start));
			if (defUnit != null) {
				defStart = defUnit.getMinAddress();
			}
		}
		Iterator<AddressRange> defIter = Iterators.transform(
			getDefinedUnitIterator(defStart, forward), u -> u.getRange());
		AddressRangeIterator undefIter =
			AddressRangeIterators.subtract(set.iterator(forward), defIter, start, forward);
		AddressIteratorAdapter undefAddrIter = new AddressIteratorAdapter(undefIter, forward);
		return Iterators.transform(undefAddrIter.iterator(), a -> doCreateUndefinedUnit(a));
	}

	protected AddressRangeIterator getUndefinedRangeIterator(AddressSetView set, boolean forward) {
		Iterator<AddressRange> defIter = Iterators.transform(
			getDefinedUnitIterator(set, forward), u -> u.getRange());
		return AddressRangeIterators.subtract(set.iterator(forward), defIter,
			forward ? set.getMinAddress() : set.getMaxAddress(), forward);
	}

	protected boolean isUndefinedRange(long snap, AddressRange range) {
		if (codeOperations.undefinedData().coversRange(Range.singleton(snap), range)) {
			return true;
		}
		TraceCodeUnit minUnit =
			codeOperations.definedUnits().getContaining(snap, range.getMinAddress());
		if (minUnit != null && program.isCodeVisible(minUnit, minUnit.getLifespan())) {
			return false;
		}
		TraceCodeUnit maxUnit =
			codeOperations.definedUnits().getContaining(snap, range.getMaxAddress());
		if (maxUnit != null && program.isCodeVisible(maxUnit, maxUnit.getLifespan())) {
			return false;
		}
		return true;
	}

	protected Iterator<TraceData> getUndefinedDataIterator(AddressSetView set, boolean forward) {
		AddressRangeIterator undefIter = getUndefinedRangeIterator(set, forward);
		AddressIteratorAdapter undefAddrIter = new AddressIteratorAdapter(undefIter, forward);
		return Iterators.transform(undefAddrIter.iterator(), a -> doCreateUndefinedUnit(a));
	}

	protected Iterator<TraceCodeUnit> getCodeUnitIterator(AddressSetView set, boolean forward) {
		return new MergeSortingIterator<>(List.of(
			getDefinedUnitIterator(set, forward),
			getUndefinedDataIterator(set, forward)),
			getUnitComparator(forward));
	}

	protected Iterator<TraceCodeUnit> getCodeUnitIterator(Address start, boolean forward) {
		return new MergeSortingIterator<>(List.of(
			getDefinedUnitIterator(start, forward),
			getUndefinedDataIterator(start, forward)),
			getUnitComparator(forward));
	}

	protected Iterator<TraceCodeUnit> getCodeUnitIterator(boolean forward) {
		AddressSetView set = program.allAddresses;
		return getCodeUnitIterator(forward ? set.getMinAddress() : set.getMaxAddress(), forward);
	}

	protected Iterator<TraceData> getDataIterator(AddressSetView set, boolean forward) {
		return new MergeSortingIterator<>(List.of(
			getDefinedDataIterator(set, forward),
			getUndefinedDataIterator(set, forward)),
			getUnitComparator(forward));
	}

	protected Iterator<TraceData> getDataIterator(Address start, boolean forward) {
		return new MergeSortingIterator<>(List.of(
			getDefinedDataIterator(start, forward),
			getUndefinedDataIterator(start, forward)),
			getUnitComparator(forward));
	}

	protected Iterator<TraceData> getDataIterator(boolean forward) {
		AddressSetView set = program.allAddresses;
		return getDataIterator(forward ? set.getMinAddress() : set.getMaxAddress(), forward);
	}

	@Override
	public CodeUnit getCodeUnitAt(Address addr) {
		CodeUnit containing = getCodeUnitContaining(addr);
		if (containing == null) {
			return doCreateUndefinedUnit(addr);
		}
		if (!containing.getMinAddress().equals(addr)) {
			return null;
		}
		return containing;
	}

	@Override
	public CodeUnit getCodeUnitContaining(Address addr) {
		try (LockHold hold = program.trace.lockRead()) {
			return orUndef(getTopCode(s -> codeOperations.definedUnits().getContaining(s, addr)),
				addr);
		}
	}

	@Override
	public CodeUnit getCodeUnitAfter(Address addr) {
		addr = addr.next();
		try (LockHold hold = program.trace.lockRead()) {
			return addr == null ? null : next(getCodeUnitIterator(addr, true));
		}
	}

	@Override
	public CodeUnit getCodeUnitBefore(Address addr) {
		addr = addr.previous();
		try (LockHold hold = program.trace.lockRead()) {
			return addr == null ? null : next(getCodeUnitIterator(addr, false));
		}
	}

	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, boolean forward) {
		// HACK
		if (CodeUnit.INSTRUCTION_PROPERTY.equals(property)) {
			return new WrappingCodeUnitIterator(getInstructionIterator(forward));
		}
		// TODO: Other "special" property types

		// TODO: Cover this in testing
		TracePropertyMap<?> map =
			program.trace.getAddressPropertyManager().getPropertyMap(property);
		if (map == null) {
			return new WrappingCodeUnitIterator(Collections.emptyIterator());
		}
		// TODO: The property map doesn't heed forking.
		return new WrappingCodeUnitIterator(NestedIterator.start(
			map.getAddressSetView(Range.singleton(program.snap)).iterator(forward),
			rng -> getTopCodeIterator(
				s -> codeOperations.codeUnits().get(s, rng, forward).iterator(),
				forward)));
	}

	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, Address addr, boolean forward) {
		// HACK
		if (CodeUnit.INSTRUCTION_PROPERTY.equals(property)) {
			return new WrappingCodeUnitIterator(getInstructionIterator(addr, forward));
		}
		// TODO: Other "special" property types

		// TODO: Cover this in testing
		TracePropertyMap<?> map =
			program.trace.getAddressPropertyManager().getPropertyMap(property);
		if (map == null) {
			return new WrappingCodeUnitIterator(Collections.emptyIterator());
		}
		// TODO: The property map doesn't heed forking.
		return new WrappingCodeUnitIterator(NestedIterator.start(
			map.getAddressSetView(Range.singleton(program.snap)).iterator(addr, forward),
			rng -> getTopCodeIterator(
				s -> codeOperations.codeUnits().get(s, rng, forward).iterator(),
				forward)));
	}

	@Override
	public CodeUnitIterator getCodeUnitIterator(String property, AddressSetView addrSet,
			boolean forward) {
		// HACK
		if (CodeUnit.INSTRUCTION_PROPERTY.equals(property)) {
			return new WrappingCodeUnitIterator(getInstructionIterator(addrSet, forward));
		}
		// TODO: Other "special" property types

		// TODO: Cover this in testing
		TracePropertyMap<?> map =
			program.trace.getAddressPropertyManager().getPropertyMap(property);
		if (map == null) {
			return new WrappingCodeUnitIterator(Collections.emptyIterator());
		}
		// TODO: The property map doesn't heed forking.
		return new WrappingCodeUnitIterator(NestedIterator.start(
			new IntersectionAddressSetView(map.getAddressSetView(Range.singleton(program.snap)),
				addrSet).iterator(forward),
			rng -> getTopCodeIterator(
				s -> codeOperations.codeUnits().get(s, rng, forward).iterator(),
				forward)));
	}

	@Override
	public CodeUnitIterator getCommentCodeUnitIterator(int commentType, AddressSetView addrSet) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AddressIterator getCommentAddressIterator(int commentType, AddressSetView addrSet,
			boolean forward) {
		return new IntersectionAddressSetView(addrSet, program.viewport.unionedAddresses(
			s -> program.trace.getCommentAdapter()
					.getAddressSetView(Range.singleton(s), e -> e.getType() == commentType)))
							.getAddresses(forward);
	}

	@Override
	public AddressIterator getCommentAddressIterator(AddressSetView addrSet, boolean forward) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getComment(int commentType, Address address) {
		try (LockHold hold = program.trace.lockRead()) {
			return program.viewport.getTop(
				s -> program.trace.getCommentAdapter().getComment(s, address, commentType));
		}
	}

	@Override
	public void setComment(Address address, int commentType, String comment) {
		program.trace.getCommentAdapter()
				.setComment(Range.atLeast(program.snap), address,
					commentType, comment);
	}

	@Override
	public CodeUnitIterator getCodeUnits(boolean forward) {
		return new WrappingCodeUnitIterator(getCodeUnitIterator(forward));
	}

	@Override
	public CodeUnitIterator getCodeUnits(Address start, boolean forward) {
		return new WrappingCodeUnitIterator(getCodeUnitIterator(start, forward));
	}

	@Override
	public CodeUnitIterator getCodeUnits(AddressSetView addressSet, boolean forward) {
		return new WrappingCodeUnitIterator(getCodeUnitIterator(addressSet, forward));
	}

	@Override
	public Instruction getInstructionAt(Address addr) {
		try (LockHold hold = program.trace.lockRead()) {
			return getTopCode(s -> codeOperations.instructions().getAt(s, addr));
		}
	}

	@Override
	public Instruction getInstructionContaining(Address addr) {
		try (LockHold hold = program.trace.lockRead()) {
			return getTopCode(s -> codeOperations.instructions().getContaining(s, addr));
		}
	}

	@Override
	public Instruction getInstructionAfter(Address addr) {
		addr = addr.next();
		try (LockHold hold = program.trace.lockRead()) {
			return addr == null ? null : next(getInstructionIterator(addr, true));
		}
	}

	@Override
	public Instruction getInstructionBefore(Address addr) {
		addr = addr.previous();
		try (LockHold hold = program.trace.lockRead()) {
			return addr == null ? null : next(getInstructionIterator(addr, false));
		}
	}

	@Override
	public InstructionIterator getInstructions(boolean forward) {
		return new WrappingInstructionIterator(getInstructionIterator(forward));
	}

	@Override
	public InstructionIterator getInstructions(Address start, boolean forward) {
		return new WrappingInstructionIterator(getInstructionIterator(start, forward));
	}

	@Override
	public InstructionIterator getInstructions(AddressSetView addressSet, boolean forward) {
		return new WrappingInstructionIterator(getInstructionIterator(addressSet, forward));
	}

	@Override
	public Data getDataAt(Address addr) {
		CodeUnit containing = getCodeUnitContaining(addr);
		if (containing == null) {
			return doCreateUndefinedUnit(addr);
		}
		if (!(containing instanceof Data)) {
			return null;
		}
		if (!containing.getMinAddress().equals(addr)) {
			return null;
		}
		return (Data) containing;
	}

	@Override
	public Data getDataContaining(Address addr) {
		CodeUnit cu = getCodeUnitContaining(addr);
		if (cu instanceof Data) {
			return (Data) cu;
		}
		return null;
	}

	@Override
	public Data getDataAfter(Address addr) {
		addr = addr.next();
		try (LockHold hold = program.trace.lockRead()) {
			return addr == null ? null : next(getDataIterator(addr, true));
		}
	}

	@Override
	public Data getDataBefore(Address addr) {
		addr = addr.previous();
		try (LockHold hold = program.trace.lockRead()) {
			return addr == null ? null : next(getDataIterator(addr, false));
		}
	}

	@Override
	public DataIterator getData(boolean forward) {
		return new WrappingDataIterator(getDataIterator(forward));
	}

	@Override
	public DataIterator getData(Address start, boolean forward) {
		return new WrappingDataIterator(getDataIterator(start, forward));
	}

	@Override
	public DataIterator getData(AddressSetView addressSet, boolean forward) {
		return new WrappingDataIterator(getDataIterator(addressSet, forward));
	}

	@Override
	public Data getDefinedDataAt(Address addr) {
		try (LockHold hold = program.trace.lockRead()) {
			return getTopCode(s -> codeOperations.definedData().getAt(s, addr));
		}
	}

	@Override
	public Data getDefinedDataContaining(Address addr) {
		try (LockHold hold = program.trace.lockRead()) {
			return getTopCode(s -> codeOperations.definedData().getContaining(s, addr));
		}
	}

	@Override
	public Data getDefinedDataAfter(Address addr) {
		addr = addr.next();
		try (LockHold hold = program.trace.lockRead()) {
			return addr == null ? null : next(getDefinedDataIterator(addr, true));
		}
	}

	@Override
	public Data getDefinedDataBefore(Address addr) {
		addr = addr.previous();
		try (LockHold hold = program.trace.lockRead()) {
			return addr == null ? null : next(getDefinedDataIterator(addr, false));
		}
	}

	@Override
	public DataIterator getDefinedData(boolean forward) {
		return new WrappingDataIterator(getDefinedDataIterator(forward));
	}

	@Override
	public DataIterator getDefinedData(Address start, boolean forward) {
		return new WrappingDataIterator(getDefinedDataIterator(start, forward));
	}

	@Override
	public DataIterator getDefinedData(AddressSetView addressSet, boolean forward) {
		return new WrappingDataIterator(getDefinedDataIterator(addressSet, forward));
	}

	@Override
	public Data getUndefinedDataAt(Address addr) {
		try (LockHold hold = program.trace.lockRead()) {
			return reqUndef(getTopCode(s -> codeOperations.definedUnits().getContaining(s, addr)),
				addr);
		}
	}

	@Override
	public Data getUndefinedDataAfter(Address addr, TaskMonitor monitor) {
		addr = addr.next();
		try (LockHold hold = program.trace.lockRead()) {
			return addr == null ? null : next(getUndefinedDataIterator(addr, true));
		}
	}

	@Override
	public Data getUndefinedDataBefore(Address addr, TaskMonitor monitor) {
		addr = addr.previous();
		try (LockHold hold = program.trace.lockRead()) {
			return addr == null ? null : next(getUndefinedDataIterator(addr, false));
		}
	}

	@Override
	public Data getFirstUndefinedData(AddressSetView addressSet, TaskMonitor monitor) {
		try (LockHold hold = program.trace.lockRead()) {
			return next(getUndefinedDataIterator(addressSet, true));
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote This could maybe use a (lazy) view; however, to be consistent with expectations
	 *           established by {@link ProgramDB}, it constructs the actual set, and permits
	 *           cancellation by the monitor.
	 */
	@Override
	public AddressSet getUndefinedRanges(AddressSetView set, boolean initializedMemoryOnly,
			TaskMonitor monitor) throws CancelledException {
		AddressSet result = new AddressSet();
		for (AddressRange range : getUndefinedRangeIterator(set, true)) {
			result.add(range);
			monitor.checkCanceled();
		}
		return result;
	}

	@Override
	public CodeUnit getDefinedCodeUnitAfter(Address addr) {
		addr = addr.next();
		try (LockHold hold = program.trace.lockRead()) {
			return next(getDefinedUnitIterator(addr, true));
		}
	}

	@Override
	public CodeUnit getDefinedCodeUnitBefore(Address addr) {
		addr = addr.previous();
		try (LockHold hold = program.trace.lockRead()) {
			return next(getDefinedUnitIterator(addr, false));
		}
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
		DBTraceMemoryRegion region = program.memory.getTopRegion(
			s -> program.trace.getMemoryManager().getRegionContaining(s, addr));
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
		DBTraceMemoryRegion region = program.memory.getTopRegion(
			s -> program.trace.getMemoryManager().getLiveRegionByPath(s, name));
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
		// TODO: See getNumCodeUnits... Why was this Long.MAX_VALUE before?
		return codeOperations.instructions().size();
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
