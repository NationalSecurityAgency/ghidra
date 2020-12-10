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
import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

import org.junit.*;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.listing.DBTraceCodeManager;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DBTraceProgramViewListingTest extends AbstractGhidraHeadlessIntegrationTest {
	protected Language toy;
	protected DBTrace trace;
	protected DBTraceProgramView view;
	protected DBTraceProgramViewListing listing; // TODO: Do I want to expose the internal types?
	protected DBTraceMemoryManager memory;
	protected DBTraceCodeManager code;

	protected Data addData(long snap, Address address, DataType type, int... bytes)
			throws CodeUnitInsertionException {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Add Data", true)) {
			memory.putBytes(snap, address, buf(bytes));
			Data data =
				code.definedData().create(Range.closed(snap, snap), address, type, bytes.length);
			assertEquals(bytes.length, data.getLength());
			return data;
		}
	}

	protected Instruction addInstruction(long snap, Address address, int... bytes)
			throws InsufficientBytesException, UnknownInstructionException,
			CodeUnitInsertionException {
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Add Instruction", true)) {
			memory.putBytes(snap, address, buf(bytes));
			ProcessorContext ctx = new ProgramProcessorContext(
				trace.getFixedProgramView(snap).getProgramContext(), address);
			InstructionPrototype prototype =
				toy.parse(memory.getBufferAt(snap, address), ctx, false);
			Instruction ins =
				code.instructions().create(Range.closed(snap, snap), address, prototype, ctx);
			assertEquals(bytes.length, ins.getLength());
			return ins;
		}
	}

	protected Address addr(long offset) {
		return toy.getDefaultSpace().getAddress(offset);
	}

	protected AddressRange rng(long min, long max) {
		return new AddressRangeImpl(addr(min), addr(max));
	}

	protected AddressRange rng(long addr) {
		return new AddressRangeImpl(addr(addr), addr(addr));
	}

	protected AddressSetView set(AddressRange... ranges) {
		AddressSet result = new AddressSet();
		for (AddressRange r : ranges) {
			result.add(r);
		}
		return result;
	}

	protected byte[] arr(int... e) {
		byte[] result = new byte[e.length];
		for (int i = 0; i < e.length; i++) {
			result[i] = (byte) e[i];
		}
		return result;
	}

	protected ByteBuffer buf(int... e) {
		return ByteBuffer.wrap(arr(e));
	}

	protected static void assertUndefined(CodeUnit cu) {
		Data data = (Data) cu;
		assertEquals(DataType.DEFAULT, data.getDataType());
		assertFalse(data.isDefined());
	}

	protected <T> List<T> takeN(int n, Iterator<T> it) {
		List<T> result = new ArrayList<>(n);
		for (int i = 0; i < n && it.hasNext(); i++) {
			result.add(it.next());
		}
		return result;
	}

	@Before
	public void setUpTraceProgramViewListingTest() throws LanguageNotFoundException, IOException {
		toy = DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID("Toy:BE:64:default"));
		trace = new DBTrace("Testing", toy.getDefaultCompilerSpec(), this);
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Initialize", true)) {
			trace.getTimeManager().createSnapshot("Created");
		}
		memory = trace.getMemoryManager();
		code = trace.getCodeManager();
		// NOTE: First snap has to exist first
		view = trace.getProgramView();
		listing = view.getListing();
	}

	@Test
	public void testGetProgram() {
		assertEquals(view, listing.getProgram());
	}

	@Test
	public void testGetTrace() {
		assertEquals(trace, listing.getTrace());
	}

	@Test
	public void testGetSnap() {
		assertEquals(0, listing.getSnap());
	}

	@Test
	public void testAddData() throws CodeUnitInsertionException {
		Data data = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(trace.getDataTypeManager()
				.resolve(Undefined4DataType.dataType,
					DataTypeConflictHandler.DEFAULT_HANDLER),
			data.getDataType());
		assertEquals(new Scalar(32, 0x01020304), data.getValue());
	}

	@Test
	public void testAddInstruction() throws InsufficientBytesException, UnknownInstructionException,
			CodeUnitInsertionException {
		Instruction ins = addInstruction(0, addr(0x4005), 0xf4, 0);
		assertEquals("ret", ins.toString());
	}

	@Test
	public void testGetCodeUnitAt() throws CodeUnitInsertionException, InsufficientBytesException,
			UnknownInstructionException {
		assertUndefined(listing.getCodeUnitAt(addr(0x4000)));
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getCodeUnitAt(addr(0x4000)));
		assertNull(listing.getCodeUnitAt(addr(0x4001)));
		assertNull(listing.getCodeUnitAt(addr(0x4002)));
		assertNull(listing.getCodeUnitAt(addr(0x4003)));
		assertUndefined(listing.getCodeUnitAt(addr(0x4004)));

		assertUndefined(listing.getCodeUnitAt(addr(0x4005)));
		Instruction i4005 = addInstruction(0, addr(0x4005), 0xf4, 0);
		assertEquals(i4005, listing.getCodeUnitAt(addr(0x4005)));
		assertNull(listing.getCodeUnitAt(addr(0x4006)));
		assertUndefined(listing.getCodeUnitAt(addr(0x4007)));
	}

	@Test
	public void testGetCodeUnitContaining() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		assertUndefined(listing.getCodeUnitContaining(addr(0x4000)));
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getCodeUnitContaining(addr(0x4000)));
		assertEquals(d4000, listing.getCodeUnitContaining(addr(0x4001)));
		assertEquals(d4000, listing.getCodeUnitContaining(addr(0x4002)));
		assertEquals(d4000, listing.getCodeUnitContaining(addr(0x4003)));
		assertUndefined(listing.getCodeUnitContaining(addr(0x4004)));

		assertUndefined(listing.getCodeUnitContaining(addr(0x4005)));
		Instruction i4005 = addInstruction(0, addr(0x4005), 0xf4, 0);
		assertEquals(i4005, listing.getCodeUnitContaining(addr(0x4005)));
		assertEquals(i4005, listing.getCodeUnitContaining(addr(0x4006)));
		assertUndefined(listing.getCodeUnitAt(addr(0x4007)));
	}

	@Test
	public void testGetCodeUnitAfter() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		CodeUnit cu;

		assertUndefined(cu = listing.getCodeUnitAfter(addr(0x3fff)));
		assertEquals(addr(0x4000), cu.getAddress());
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getCodeUnitAfter(addr(0x3fff)));
		assertUndefined(cu = listing.getCodeUnitAfter(addr(0x4000)));
		assertEquals(addr(0x4004), cu.getAddress());

		assertUndefined(cu = listing.getCodeUnitAfter(addr(0x4004)));
		assertEquals(addr(0x4005), cu.getAddress());
		Instruction i4005 = addInstruction(0, addr(0x4005), 0xf4, 0);
		assertEquals(i4005, listing.getCodeUnitAfter(addr(0x4004)));
		assertUndefined(cu = listing.getCodeUnitAfter(addr(0x4005)));
		assertEquals(addr(0x4007), cu.getAddress());
	}

	@Test
	public void testGetCodeUnitBefore() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		CodeUnit cu;

		assertUndefined(cu = listing.getCodeUnitBefore(addr(0x4001)));
		assertEquals(addr(0x4000), cu.getAddress());
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getCodeUnitBefore(addr(0x4001)));
		assertUndefined(cu = listing.getCodeUnitBefore(addr(0x4000)));
		assertEquals(addr(0x3fff), cu.getAddress());

		assertUndefined(cu = listing.getCodeUnitBefore(addr(0x4006)));
		assertEquals(addr(0x4005), cu.getAddress());
		Instruction i4005 = addInstruction(0, addr(0x4005), 0xf4, 0);
		assertEquals(i4005, listing.getCodeUnitBefore(addr(0x4006)));
		assertUndefined(cu = listing.getCodeUnitBefore(addr(0x4005)));
		assertEquals(addr(0x4004), cu.getAddress());
	}

	@Test
	public void testGetCodeUnits() throws CodeUnitInsertionException, InsufficientBytesException,
			UnknownInstructionException {
		List<CodeUnit> sample;
		AddressSet set;

		sample = takeN(10, listing.getCodeUnits(true));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(addr(i), cu.getAddress());
		}

		sample = takeN(10, listing.getCodeUnits(false));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(addr(-1 - i), cu.getAddress());
		}

		sample = takeN(10, listing.getCodeUnits(addr(0x3fff), true));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(addr(0x3fff + i), cu.getAddress());
		}

		sample = takeN(10, listing.getCodeUnits(addr(0x4008), false));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(addr(0x4008 - i), cu.getAddress());
		}

		set = new AddressSet();
		set.add(addr(0x3ffe));
		set.add(rng(0x4000, 0x4003));
		set.add(addr(0x4005)); // Range only restricts start addresses
		set.add(rng(0x4007, 0x4008));
		sample = takeN(10, listing.getCodeUnits(set, true));
		assertEquals(8, sample.size());
		assertEquals(addr(0x3ffe), sample.get(0).getAddress());
		assertEquals(addr(0x4000), sample.get(1).getAddress());
		assertEquals(addr(0x4001), sample.get(2).getAddress());
		assertEquals(addr(0x4002), sample.get(3).getAddress());
		assertEquals(addr(0x4003), sample.get(4).getAddress());
		assertEquals(addr(0x4005), sample.get(5).getAddress());
		assertEquals(addr(0x4007), sample.get(6).getAddress());
		assertEquals(addr(0x4008), sample.get(7).getAddress());

		sample = takeN(10, listing.getCodeUnits(set, false));
		assertEquals(8, sample.size());
		assertEquals(addr(0x4008), sample.get(0).getAddress());
		assertEquals(addr(0x4007), sample.get(1).getAddress());
		assertEquals(addr(0x4005), sample.get(2).getAddress());
		assertEquals(addr(0x4003), sample.get(3).getAddress());
		assertEquals(addr(0x4002), sample.get(4).getAddress());
		assertEquals(addr(0x4001), sample.get(5).getAddress());
		assertEquals(addr(0x4000), sample.get(6).getAddress());
		assertEquals(addr(0x3ffe), sample.get(7).getAddress());

		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		Instruction i4005 = addInstruction(0, addr(0x4005), 0xf4, 0);

		sample = takeN(10, listing.getCodeUnits(true));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(addr(i), cu.getAddress());
		}

		sample = takeN(10, listing.getCodeUnits(false));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(addr(-1 - i), cu.getAddress());
		}

		sample = takeN(5, listing.getCodeUnits(addr(0x3fff), true));
		assertEquals(5, sample.size());
		assertUndefined(sample.get(0));
		assertEquals(addr(0x3fff), sample.get(0).getAddress());
		assertEquals(d4000, sample.get(1));
		assertUndefined(sample.get(2));
		assertEquals(addr(0x4004), sample.get(2).getAddress());
		assertEquals(i4005, sample.get(3));
		assertUndefined(sample.get(4));
		assertEquals(addr(0x4007), sample.get(4).getAddress());

		sample = takeN(5, listing.getCodeUnits(addr(0x4007), false));
		assertEquals(5, sample.size());
		assertUndefined(sample.get(0));
		assertEquals(addr(0x4007), sample.get(0).getAddress());
		assertEquals(i4005, sample.get(1));
		assertUndefined(sample.get(2));
		assertEquals(addr(0x4004), sample.get(2).getAddress());
		assertEquals(d4000, sample.get(3));
		assertUndefined(sample.get(4));
		assertEquals(addr(0x3fff), sample.get(4).getAddress());

		sample = takeN(10, listing.getCodeUnits(set, true));
		assertEquals(5, sample.size());
		assertEquals(addr(0x3ffe), sample.get(0).getAddress());
		assertEquals(d4000, sample.get(1));
		assertEquals(i4005, sample.get(2));
		assertEquals(addr(0x4007), sample.get(3).getAddress());
		assertEquals(addr(0x4008), sample.get(4).getAddress());

		sample = takeN(10, listing.getCodeUnits(set, false));
		assertEquals(5, sample.size());
		assertEquals(addr(0x4008), sample.get(0).getAddress());
		assertEquals(addr(0x4007), sample.get(1).getAddress());
		assertEquals(i4005, sample.get(2));
		assertEquals(d4000, sample.get(3));
		assertEquals(addr(0x3ffe), sample.get(4).getAddress());
	}

	@Test
	public void testGetInstructionAt() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		assertNull(listing.getInstructionAt(addr(0x4005)));
		Instruction i4005 = addInstruction(0, addr(0x4005), 0xf4, 0);
		assertEquals(i4005, listing.getInstructionAt(addr(0x4005)));
		assertNull(listing.getInstructionAt(addr(0x4006)));
		assertNull(listing.getInstructionAt(addr(0x4007)));
	}

	@Test
	public void testGetInstructionContaining() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		assertNull(listing.getInstructionContaining(addr(0x4005)));
		Instruction i4005 = addInstruction(0, addr(0x4005), 0xf4, 0);
		assertEquals(i4005, listing.getInstructionContaining(addr(0x4005)));
		assertEquals(i4005, listing.getInstructionContaining(addr(0x4006)));
		assertNull(listing.getInstructionContaining(addr(0x4007)));
	}

	@Test
	public void testGetInstructionAfter() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		assertNull(listing.getInstructionAfter(addr(0x4004)));
		Instruction i4005 = addInstruction(0, addr(0x4005), 0xf4, 0);
		assertEquals(i4005, listing.getInstructionAfter(addr(0x4004)));
		assertNull(listing.getInstructionAfter(addr(0x4005)));
	}

	@Test
	public void testGetInstructionBefore() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		assertNull(listing.getInstructionBefore(addr(0x4006)));
		Instruction i4005 = addInstruction(0, addr(0x4005), 0xf4, 0);
		assertEquals(i4005, listing.getInstructionBefore(addr(0x4006)));
		assertNull(listing.getInstructionBefore(addr(0x4005)));
	}

	@Test
	public void testGetInstructions() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		AddressSet set;

		assertTrue(takeN(10, listing.getInstructions(true)).isEmpty());
		assertTrue(takeN(10, listing.getInstructions(false)).isEmpty());
		assertTrue(takeN(10, listing.getInstructions(addr(0x4006), true)).isEmpty());
		assertTrue(takeN(10, listing.getInstructions(addr(0x4008), false)).isEmpty());

		set = new AddressSet();
		set.add(addr(0x3ffe));
		set.add(rng(0x4000, 0x4003));
		set.add(addr(0x4005)); // Range only restricts start addresses
		set.add(rng(0x4007, 0x4008));
		assertTrue(takeN(10, listing.getInstructions(set, true)).isEmpty());
		assertTrue(takeN(10, listing.getInstructions(set, false)).isEmpty());

		Instruction i4005 = addInstruction(0, addr(0x4005), 0xf4, 0);
		Instruction i4007 = addInstruction(0, addr(0x4007), 0xf4, 0);
		Instruction i400a = addInstruction(0, addr(0x400a), 0xf4, 0);
		addData(0, addr(0x400c), Undefined4DataType.dataType, 1, 2, 3, 4);

		assertEquals(List.of(i4005, i4007, i400a), takeN(10, listing.getInstructions(true)));
		assertEquals(List.of(i400a, i4007, i4005), takeN(10, listing.getInstructions(false)));
		assertEquals(List.of(i4007, i400a), takeN(10, listing.getInstructions(addr(0x4006), true)));
		assertEquals(List.of(i4007, i4005),
			takeN(10, listing.getInstructions(addr(0x4008), false)));

		assertEquals(List.of(i4005, i4007), takeN(10, listing.getInstructions(set, true)));
		assertEquals(List.of(i4007, i4005), takeN(10, listing.getInstructions(set, false)));
	}

	@Test
	public void testGetDataAt() throws CodeUnitInsertionException, InsufficientBytesException,
			UnknownInstructionException {
		assertUndefined(listing.getDataAt(addr(0x4000)));
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getDataAt(addr(0x4000)));
		assertNull(listing.getDataAt(addr(0x4001)));
		assertNull(listing.getDataAt(addr(0x4002)));
		assertNull(listing.getDataAt(addr(0x4003)));
		assertUndefined(listing.getDataAt(addr(0x4004)));

		assertUndefined(listing.getDataAt(addr(0x4005)));
		addInstruction(0, addr(0x4005), 0xf4, 0);
		assertNull(listing.getDataAt(addr(0x4005)));
		assertNull(listing.getDataAt(addr(0x4006)));
		assertUndefined(listing.getDataAt(addr(0x4007)));
	}

	@Test
	public void testGetDataContaining() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		assertUndefined(listing.getDataContaining(addr(0x4000)));
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getDataContaining(addr(0x4000)));
		assertEquals(d4000, listing.getDataContaining(addr(0x4001)));
		assertEquals(d4000, listing.getDataContaining(addr(0x4002)));
		assertEquals(d4000, listing.getDataContaining(addr(0x4003)));
		assertUndefined(listing.getDataContaining(addr(0x4004)));

		assertUndefined(listing.getDataContaining(addr(0x4005)));
		addInstruction(0, addr(0x4005), 0xf4, 0);
		assertNull(listing.getDataContaining(addr(0x4005)));
		assertNull(listing.getDataContaining(addr(0x4006)));
		assertUndefined(listing.getDataContaining(addr(0x4007)));
	}

	@Test
	public void testGetDataAfter() throws CodeUnitInsertionException, InsufficientBytesException,
			UnknownInstructionException {
		CodeUnit cu;

		assertUndefined(cu = listing.getDataAfter(addr(0x3fff)));
		assertEquals(addr(0x4000), cu.getAddress());
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getDataAfter(addr(0x3fff)));
		assertUndefined(cu = listing.getDataAfter(addr(0x4000)));
		assertEquals(addr(0x4004), cu.getAddress());

		assertUndefined(cu = listing.getDataAfter(addr(0x4004)));
		assertEquals(addr(0x4005), cu.getAddress());
		addInstruction(0, addr(0x4005), 0xf4, 0);
		assertUndefined(cu = listing.getDataAfter(addr(0x4004)));
		assertEquals(addr(0x4007), cu.getAddress());
	}

	@Test
	public void testGetDataBefore() throws CodeUnitInsertionException, InsufficientBytesException,
			UnknownInstructionException {
		CodeUnit cu;

		assertUndefined(cu = listing.getDataBefore(addr(0x4001)));
		assertEquals(addr(0x4000), cu.getAddress());
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getDataBefore(addr(0x4001)));
		assertUndefined(cu = listing.getDataBefore(addr(0x4000)));
		assertEquals(addr(0x3fff), cu.getAddress());

		assertUndefined(cu = listing.getDataBefore(addr(0x4006)));
		assertEquals(addr(0x4005), cu.getAddress());
		addInstruction(0, addr(0x4005), 0xf4, 0);
		assertUndefined(cu = listing.getDataBefore(addr(0x4007)));
		assertEquals(addr(0x4004), cu.getAddress());
	}

	@Test
	public void testGetData() throws CodeUnitInsertionException, InsufficientBytesException,
			UnknownInstructionException {
		List<Data> sample;
		AddressSet set;

		sample = takeN(10, listing.getData(true));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(addr(i), cu.getAddress());
		}

		sample = takeN(10, listing.getData(false));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(addr(-1 - i), cu.getAddress());
		}

		sample = takeN(10, listing.getData(addr(0x3fff), true));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(addr(0x3fff + i), cu.getAddress());
		}

		sample = takeN(10, listing.getData(addr(0x4008), false));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(addr(0x4008 - i), cu.getAddress());
		}

		set = new AddressSet();
		set.add(addr(0x3ffe));
		set.add(rng(0x4000, 0x4003));
		set.add(addr(0x4005)); // Range only restricts start addresses
		set.add(rng(0x4007, 0x4008));
		sample = takeN(10, listing.getData(set, true));
		assertEquals(8, sample.size());
		assertEquals(addr(0x3ffe), sample.get(0).getAddress());
		assertEquals(addr(0x4000), sample.get(1).getAddress());
		assertEquals(addr(0x4001), sample.get(2).getAddress());
		assertEquals(addr(0x4002), sample.get(3).getAddress());
		assertEquals(addr(0x4003), sample.get(4).getAddress());
		assertEquals(addr(0x4005), sample.get(5).getAddress());
		assertEquals(addr(0x4007), sample.get(6).getAddress());
		assertEquals(addr(0x4008), sample.get(7).getAddress());

		sample = takeN(10, listing.getData(set, false));
		assertEquals(8, sample.size());
		assertEquals(addr(0x4008), sample.get(0).getAddress());
		assertEquals(addr(0x4007), sample.get(1).getAddress());
		assertEquals(addr(0x4005), sample.get(2).getAddress());
		assertEquals(addr(0x4003), sample.get(3).getAddress());
		assertEquals(addr(0x4002), sample.get(4).getAddress());
		assertEquals(addr(0x4001), sample.get(5).getAddress());
		assertEquals(addr(0x4000), sample.get(6).getAddress());
		assertEquals(addr(0x3ffe), sample.get(7).getAddress());

		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		addInstruction(0, addr(0x4005), 0xf4, 0);

		sample = takeN(10, listing.getData(true));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(addr(i), cu.getAddress());
		}

		sample = takeN(10, listing.getData(false));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(addr(-1 - i), cu.getAddress());
		}

		sample = takeN(4, listing.getData(addr(0x3fff), true));
		assertEquals(4, sample.size());
		assertUndefined(sample.get(0));
		assertEquals(addr(0x3fff), sample.get(0).getAddress());
		assertEquals(d4000, sample.get(1));
		assertUndefined(sample.get(2));
		assertEquals(addr(0x4004), sample.get(2).getAddress());
		assertUndefined(sample.get(3));
		assertEquals(addr(0x4007), sample.get(3).getAddress());

		sample = takeN(4, listing.getData(addr(0x4007), false));
		assertEquals(4, sample.size());
		assertUndefined(sample.get(0));
		assertEquals(addr(0x4007), sample.get(0).getAddress());
		assertUndefined(sample.get(1));
		assertEquals(addr(0x4004), sample.get(1).getAddress());
		assertEquals(d4000, sample.get(2));
		assertUndefined(sample.get(3));
		assertEquals(addr(0x3fff), sample.get(3).getAddress());

		sample = takeN(10, listing.getData(set, true));
		assertEquals(4, sample.size());
		assertEquals(addr(0x3ffe), sample.get(0).getAddress());
		assertEquals(d4000, sample.get(1));
		assertEquals(addr(0x4007), sample.get(2).getAddress());
		assertEquals(addr(0x4008), sample.get(3).getAddress());

		sample = takeN(10, listing.getData(set, false));
		assertEquals(4, sample.size());
		assertEquals(addr(0x4008), sample.get(0).getAddress());
		assertEquals(addr(0x4007), sample.get(1).getAddress());
		assertEquals(d4000, sample.get(2));
		assertEquals(addr(0x3ffe), sample.get(3).getAddress());
	}

	@Test
	public void testGetDefinedDataAt() throws CodeUnitInsertionException {
		assertNull(listing.getDefinedDataAt(addr(0x4000)));
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getDefinedDataAt(addr(0x4000)));
		assertNull(listing.getDefinedDataAt(addr(0x4001)));
		assertNull(listing.getDefinedDataAt(addr(0x4002)));
		assertNull(listing.getDefinedDataAt(addr(0x4003)));
		assertNull(listing.getDefinedDataAt(addr(0x4004)));
		assertNull(listing.getDefinedDataAt(addr(0x4005)));
	}

	@Test
	public void testGetDefinedDataContaining() throws CodeUnitInsertionException {
		assertNull(listing.getDefinedDataContaining(addr(0x4005)));
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getDefinedDataContaining(addr(0x4000)));
		assertEquals(d4000, listing.getDefinedDataContaining(addr(0x4001)));
		assertEquals(d4000, listing.getDefinedDataContaining(addr(0x4002)));
		assertEquals(d4000, listing.getDefinedDataContaining(addr(0x4003)));
		assertNull(listing.getDefinedDataContaining(addr(0x4004)));
	}

	@Test
	public void testGetDefinedDataAfter() throws CodeUnitInsertionException {
		assertNull(listing.getDefinedDataAfter(addr(0x4000)));
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getDefinedDataAfter(addr(0x3fff)));
		assertNull(listing.getDefinedDataAfter(addr(0x4000)));
	}

	@Test
	public void testGetDefinedDataBefore() throws CodeUnitInsertionException {
		assertNull(listing.getDefinedDataBefore(addr(0x4004)));
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getDefinedDataBefore(addr(0x4001)));
		assertNull(listing.getDefinedDataBefore(addr(0x4000)));
	}

	@Test
	public void testGetDefinedData() throws InsufficientBytesException, UnknownInstructionException,
			CodeUnitInsertionException {
		AddressSet set;

		assertTrue(takeN(10, listing.getDefinedData(true)).isEmpty());
		assertTrue(takeN(10, listing.getDefinedData(false)).isEmpty());
		assertTrue(takeN(10, listing.getDefinedData(addr(0x3fff), true)).isEmpty());
		assertTrue(takeN(10, listing.getDefinedData(addr(0x4009), false)).isEmpty());

		set = new AddressSet();
		set.add(addr(0x3ffe));
		set.add(rng(0x4000, 0x4002));
		set.add(addr(0x4004));
		set.add(rng(0x4007, 0x4008));
		assertTrue(takeN(10, listing.getDefinedData(set, true)).isEmpty());
		assertTrue(takeN(10, listing.getDefinedData(set, false)).isEmpty());

		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 0, 1, 2, 3);
		Data d4004 = addData(0, addr(0x4004), Undefined4DataType.dataType, 5, 6, 7, 8);
		Data d400a = addData(0, addr(0x400a), Undefined4DataType.dataType, 10, 11, 12, 13);
		addInstruction(0, addr(0x400e), 0xf4, 0);

		assertEquals(List.of(d4000, d4004, d400a), takeN(10, listing.getDefinedData(true)));
		assertEquals(List.of(d400a, d4004, d4000), takeN(10, listing.getDefinedData(false)));
		assertEquals(List.of(d4004, d400a), takeN(10, listing.getDefinedData(addr(0x4004), true)));
		assertEquals(List.of(d4004, d4000), takeN(10, listing.getDefinedData(addr(0x4004), false)));

		assertEquals(List.of(d4000, d4004), takeN(10, listing.getDefinedData(set, true)));
		assertEquals(List.of(d4004, d4000), takeN(10, listing.getDefinedData(set, false)));
	}

	@Test
	public void testGetUndefinedDataAt() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		assertUndefined(listing.getUndefinedDataAt(addr(0x4000)));
		addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertNull(listing.getUndefinedDataAt(addr(0x4000)));
		assertNull(listing.getUndefinedDataAt(addr(0x4001)));
		assertNull(listing.getUndefinedDataAt(addr(0x4002)));
		assertNull(listing.getUndefinedDataAt(addr(0x4003)));
		assertUndefined(listing.getUndefinedDataAt(addr(0x4004)));

		assertUndefined(listing.getUndefinedDataAt(addr(0x4005)));
		addInstruction(0, addr(0x4005), 0xf4, 0);
		assertNull(listing.getUndefinedDataAt(addr(0x4005)));
		assertNull(listing.getUndefinedDataAt(addr(0x4006)));
		assertUndefined(listing.getUndefinedDataAt(addr(0x4007)));
	}

	@Test
	public void testGetUndefinedDataAfter() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		Data cu;

		assertUndefined(cu = listing.getUndefinedDataAfter(addr(0x3fff), TaskMonitor.DUMMY));
		assertEquals(addr(0x4000), cu.getAddress());
		addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertUndefined(cu = listing.getUndefinedDataAfter(addr(0x3fff), TaskMonitor.DUMMY));
		assertEquals(addr(0x4004), cu.getAddress());

		assertUndefined(cu = listing.getUndefinedDataAfter(addr(0x4004), TaskMonitor.DUMMY));
		assertEquals(addr(0x4005), cu.getAddress());
		addInstruction(0, addr(0x4005), 0xf4, 0);
		assertUndefined(cu = listing.getUndefinedDataAfter(addr(0x4004), TaskMonitor.DUMMY));
		assertEquals(addr(0x4007), cu.getAddress());
	}

	@Test
	public void testGetUndefinedDataBefore() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		Data cu;

		assertUndefined(cu = listing.getUndefinedDataBefore(addr(0x4001), TaskMonitor.DUMMY));
		assertEquals(addr(0x4000), cu.getAddress());
		addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertUndefined(cu = listing.getUndefinedDataBefore(addr(0x4004), TaskMonitor.DUMMY));
		assertEquals(addr(0x3fff), cu.getAddress());

		assertUndefined(cu = listing.getUndefinedDataBefore(addr(0x4006), TaskMonitor.DUMMY));
		assertEquals(addr(0x4005), cu.getAddress());
		addInstruction(0, addr(0x4005), 0xf4, 0);
		assertUndefined(cu = listing.getUndefinedDataBefore(addr(0x4007), TaskMonitor.DUMMY));
		assertEquals(addr(0x4004), cu.getAddress());
	}

	@Test
	public void testGetFirstUndefinedData() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		addInstruction(0, addr(0x4005), 0xf4, 0);
		Data cu;

		assertUndefined(cu = listing.getFirstUndefinedData(set(rng(0x3fff)), TaskMonitor.DUMMY));
		assertEquals(addr(0x3fff), cu.getAddress());
		assertUndefined(cu = listing.getFirstUndefinedData(
			set(rng(0x4000, 0x4002), rng(0x4005, 0x400a)), TaskMonitor.DUMMY));
		assertEquals(addr(0x4007), cu.getAddress());
	}

	@Test
	@Ignore("TODO")
	public void testGetUndefinedRanges() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException, CancelledException {
		addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		addInstruction(0, addr(0x4005), 0xf4, 0);

		TODO(); // Should I expect OTHER ranges in the undefined set?
		assertEquals(set(rng(0, 0x3fff), rng(0x4004), rng(0x4007, -1)), listing.getUndefinedRanges(
			view.getAddressFactory().getAddressSet(), false, TaskMonitor.DUMMY));
	}

	@Test
	public void testGetDefinedCodeUnitAfter() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		assertNull(listing.getDefinedCodeUnitAfter(addr(0x3fff)));
		Instruction i4005 = addInstruction(0, addr(0x4005), 0xf4, 0);
		assertEquals(i4005, listing.getDefinedCodeUnitAfter(addr(0x3fff)));
		assertNull(listing.getDefinedCodeUnitAfter(addr(0x4005)));
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getDefinedCodeUnitAfter(addr(0x3fff)));
		assertEquals(i4005, listing.getDefinedCodeUnitAfter(addr(0x4000)));
	}

	@Test
	public void testGetDefinedCodeUnitBefore() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		assertNull(listing.getDefinedCodeUnitBefore(addr(0x4006)));
		Data d4000 = addData(0, addr(0x4000), Undefined4DataType.dataType, 1, 2, 3, 4);
		assertEquals(d4000, listing.getDefinedCodeUnitBefore(addr(0x4006)));
		assertNull(listing.getDefinedCodeUnitBefore(addr(0x4000)));
		Instruction i4005 = addInstruction(0, addr(0x4005), 0xf4, 0);
		assertEquals(i4005, listing.getDefinedCodeUnitBefore(addr(0x4006)));
		assertEquals(d4000, listing.getDefinedCodeUnitBefore(addr(0x4005)));
	}
}
