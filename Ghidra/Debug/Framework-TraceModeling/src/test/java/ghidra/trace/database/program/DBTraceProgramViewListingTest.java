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
import java.util.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.listing.DBTraceCodeManager;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DBTraceProgramViewListingTest extends AbstractGhidraHeadlessIntegrationTest {

	ToyDBTraceBuilder b;

	DBTraceProgramView view;
	DBTraceProgramViewListing listing; // TODO: Do I want to expose the internal types?
	DBTraceMemoryManager memory;
	DBTraceCodeManager code;

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
		b = new ToyDBTraceBuilder("Testing", ProgramBuilder._TOY64_BE);
		try (UndoableTransaction tid = b.startTransaction()) {
			b.trace.getTimeManager().createSnapshot("Created");
		}
		memory = b.trace.getMemoryManager();
		code = b.trace.getCodeManager();
		// NOTE: First snap has to exist first
		view = b.trace.getProgramView();
		listing = view.getListing();
	}

	@After
	public void tearDownTraceProgramViewListingTest() {
		if (b != null) {
			b.close();
		}
	}

	@Test
	public void testGetProgram() {
		assertEquals(view, listing.getProgram());
	}

	@Test
	public void testGetTrace() {
		assertEquals(b.trace, listing.getTrace());
	}

	@Test
	public void testGetSnap() {
		assertEquals(0, listing.getSnap());
	}

	@Test
	public void testAddData() throws CodeUnitInsertionException {
		Data data;
		try (UndoableTransaction tid = b.startTransaction()) {
			data = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(b.trace.getDataTypeManager()
				.resolve(Undefined4DataType.dataType,
					DataTypeConflictHandler.DEFAULT_HANDLER),
			data.getDataType());
		assertEquals(new Scalar(32, 0x01020304), data.getValue());
	}

	@Test
	public void testAddInstruction() throws InsufficientBytesException, UnknownInstructionException,
			CodeUnitInsertionException {
		Instruction ins;
		try (UndoableTransaction tid = b.startTransaction()) {
			ins = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertEquals("ret", ins.toString());
	}

	@Test
	public void testGetCodeUnitAt() throws CodeUnitInsertionException, InsufficientBytesException,
			UnknownInstructionException {
		assertUndefined(listing.getCodeUnitAt(b.addr(0x4000)));

		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getCodeUnitAt(b.addr(0x4000)));
		assertNull(listing.getCodeUnitAt(b.addr(0x4001)));
		assertNull(listing.getCodeUnitAt(b.addr(0x4002)));
		assertNull(listing.getCodeUnitAt(b.addr(0x4003)));
		assertUndefined(listing.getCodeUnitAt(b.addr(0x4004)));

		assertUndefined(listing.getCodeUnitAt(b.addr(0x4005)));

		Instruction i4005;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4005 = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertEquals(i4005, listing.getCodeUnitAt(b.addr(0x4005)));
		assertNull(listing.getCodeUnitAt(b.addr(0x4006)));
		assertUndefined(listing.getCodeUnitAt(b.addr(0x4007)));
	}

	@Test
	public void testGetCodeUnitContaining() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		assertUndefined(listing.getCodeUnitContaining(b.addr(0x4000)));

		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getCodeUnitContaining(b.addr(0x4000)));
		assertEquals(d4000, listing.getCodeUnitContaining(b.addr(0x4001)));
		assertEquals(d4000, listing.getCodeUnitContaining(b.addr(0x4002)));
		assertEquals(d4000, listing.getCodeUnitContaining(b.addr(0x4003)));
		assertUndefined(listing.getCodeUnitContaining(b.addr(0x4004)));

		assertUndefined(listing.getCodeUnitContaining(b.addr(0x4005)));
		Instruction i4005;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4005 = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertEquals(i4005, listing.getCodeUnitContaining(b.addr(0x4005)));
		assertEquals(i4005, listing.getCodeUnitContaining(b.addr(0x4006)));
		assertUndefined(listing.getCodeUnitAt(b.addr(0x4007)));
	}

	@Test
	public void testGetCodeUnitAfter() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		CodeUnit cu;

		assertUndefined(cu = listing.getCodeUnitAfter(b.addr(0x3fff)));
		assertEquals(b.addr(0x4000), cu.getAddress());
		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getCodeUnitAfter(b.addr(0x3fff)));
		assertUndefined(cu = listing.getCodeUnitAfter(b.addr(0x4000)));
		assertEquals(b.addr(0x4004), cu.getAddress());

		assertUndefined(cu = listing.getCodeUnitAfter(b.addr(0x4004)));
		assertEquals(b.addr(0x4005), cu.getAddress());
		Instruction i4005;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4005 = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertEquals(i4005, listing.getCodeUnitAfter(b.addr(0x4004)));
		assertUndefined(cu = listing.getCodeUnitAfter(b.addr(0x4005)));
		assertEquals(b.addr(0x4007), cu.getAddress());
	}

	@Test
	public void testGetCodeUnitBefore() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		CodeUnit cu;

		assertUndefined(cu = listing.getCodeUnitBefore(b.addr(0x4001)));
		assertEquals(b.addr(0x4000), cu.getAddress());
		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getCodeUnitBefore(b.addr(0x4001)));
		assertUndefined(cu = listing.getCodeUnitBefore(b.addr(0x4000)));
		assertEquals(b.addr(0x3fff), cu.getAddress());

		assertUndefined(cu = listing.getCodeUnitBefore(b.addr(0x4006)));
		assertEquals(b.addr(0x4005), cu.getAddress());
		Instruction i4005;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4005 = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertEquals(i4005, listing.getCodeUnitBefore(b.addr(0x4006)));
		assertUndefined(cu = listing.getCodeUnitBefore(b.addr(0x4005)));
		assertEquals(b.addr(0x4004), cu.getAddress());
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
			assertEquals(b.addr(i), cu.getAddress());
		}

		sample = takeN(10, listing.getCodeUnits(false));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(b.addr(-1 - i), cu.getAddress());
		}

		sample = takeN(10, listing.getCodeUnits(b.addr(0x3fff), true));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(b.addr(0x3fff + i), cu.getAddress());
		}

		sample = takeN(10, listing.getCodeUnits(b.addr(0x4008), false));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(b.addr(0x4008 - i), cu.getAddress());
		}

		set = new AddressSet();
		set.add(b.addr(0x3ffe));
		set.add(b.range(0x4000, 0x4003));
		set.add(b.addr(0x4005)); // Range only restricts start addresses
		set.add(b.range(0x4007, 0x4008));
		sample = takeN(10, listing.getCodeUnits(set, true));
		assertEquals(8, sample.size());
		assertEquals(b.addr(0x3ffe), sample.get(0).getAddress());
		assertEquals(b.addr(0x4000), sample.get(1).getAddress());
		assertEquals(b.addr(0x4001), sample.get(2).getAddress());
		assertEquals(b.addr(0x4002), sample.get(3).getAddress());
		assertEquals(b.addr(0x4003), sample.get(4).getAddress());
		assertEquals(b.addr(0x4005), sample.get(5).getAddress());
		assertEquals(b.addr(0x4007), sample.get(6).getAddress());
		assertEquals(b.addr(0x4008), sample.get(7).getAddress());

		sample = takeN(10, listing.getCodeUnits(set, false));
		assertEquals(8, sample.size());
		assertEquals(b.addr(0x4008), sample.get(0).getAddress());
		assertEquals(b.addr(0x4007), sample.get(1).getAddress());
		assertEquals(b.addr(0x4005), sample.get(2).getAddress());
		assertEquals(b.addr(0x4003), sample.get(3).getAddress());
		assertEquals(b.addr(0x4002), sample.get(4).getAddress());
		assertEquals(b.addr(0x4001), sample.get(5).getAddress());
		assertEquals(b.addr(0x4000), sample.get(6).getAddress());
		assertEquals(b.addr(0x3ffe), sample.get(7).getAddress());

		Data d4000;
		Instruction i4005;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
			i4005 = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}

		sample = takeN(10, listing.getCodeUnits(true));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(b.addr(i), cu.getAddress());
		}

		sample = takeN(10, listing.getCodeUnits(false));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(b.addr(-1 - i), cu.getAddress());
		}

		sample = takeN(5, listing.getCodeUnits(b.addr(0x3fff), true));
		assertEquals(5, sample.size());
		assertUndefined(sample.get(0));
		assertEquals(b.addr(0x3fff), sample.get(0).getAddress());
		assertEquals(d4000, sample.get(1));
		assertUndefined(sample.get(2));
		assertEquals(b.addr(0x4004), sample.get(2).getAddress());
		assertEquals(i4005, sample.get(3));
		assertUndefined(sample.get(4));
		assertEquals(b.addr(0x4007), sample.get(4).getAddress());

		sample = takeN(5, listing.getCodeUnits(b.addr(0x4007), false));
		assertEquals(5, sample.size());
		assertUndefined(sample.get(0));
		assertEquals(b.addr(0x4007), sample.get(0).getAddress());
		assertEquals(i4005, sample.get(1));
		assertUndefined(sample.get(2));
		assertEquals(b.addr(0x4004), sample.get(2).getAddress());
		assertEquals(d4000, sample.get(3));
		assertUndefined(sample.get(4));
		assertEquals(b.addr(0x3fff), sample.get(4).getAddress());

		sample = takeN(10, listing.getCodeUnits(set, true));
		assertEquals(5, sample.size());
		assertEquals(b.addr(0x3ffe), sample.get(0).getAddress());
		assertEquals(d4000, sample.get(1));
		assertEquals(i4005, sample.get(2));
		assertEquals(b.addr(0x4007), sample.get(3).getAddress());
		assertEquals(b.addr(0x4008), sample.get(4).getAddress());

		sample = takeN(10, listing.getCodeUnits(set, false));
		assertEquals(5, sample.size());
		assertEquals(b.addr(0x4008), sample.get(0).getAddress());
		assertEquals(b.addr(0x4007), sample.get(1).getAddress());
		assertEquals(i4005, sample.get(2));
		assertEquals(d4000, sample.get(3));
		assertEquals(b.addr(0x3ffe), sample.get(4).getAddress());
	}

	@Test
	public void testGetInstructionAt() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		assertNull(listing.getInstructionAt(b.addr(0x4005)));
		Instruction i4005;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4005 = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertEquals(i4005, listing.getInstructionAt(b.addr(0x4005)));
		assertNull(listing.getInstructionAt(b.addr(0x4006)));
		assertNull(listing.getInstructionAt(b.addr(0x4007)));
	}

	@Test
	public void testGetInstructionContaining() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		assertNull(listing.getInstructionContaining(b.addr(0x4005)));
		Instruction i4005;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4005 = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertEquals(i4005, listing.getInstructionContaining(b.addr(0x4005)));
		assertEquals(i4005, listing.getInstructionContaining(b.addr(0x4006)));
		assertNull(listing.getInstructionContaining(b.addr(0x4007)));
	}

	@Test
	public void testGetInstructionAfter() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		assertNull(listing.getInstructionAfter(b.addr(0x4004)));
		Instruction i4005;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4005 = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertEquals(i4005, listing.getInstructionAfter(b.addr(0x4004)));
		assertNull(listing.getInstructionAfter(b.addr(0x4005)));
	}

	@Test
	public void testGetInstructionBefore() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		assertNull(listing.getInstructionBefore(b.addr(0x4006)));
		Instruction i4005;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4005 = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertEquals(i4005, listing.getInstructionBefore(b.addr(0x4006)));
		assertNull(listing.getInstructionBefore(b.addr(0x4005)));
	}

	@Test
	public void testGetInstructions() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		AddressSet set;

		assertTrue(takeN(10, listing.getInstructions(true)).isEmpty());
		assertTrue(takeN(10, listing.getInstructions(false)).isEmpty());
		assertTrue(takeN(10, listing.getInstructions(b.addr(0x4006), true)).isEmpty());
		assertTrue(takeN(10, listing.getInstructions(b.addr(0x4008), false)).isEmpty());

		set = new AddressSet();
		set.add(b.addr(0x3ffe));
		set.add(b.range(0x4000, 0x4003));
		set.add(b.addr(0x4005)); // Range only restricts start addresses
		set.add(b.range(0x4007, 0x4008));
		assertTrue(takeN(10, listing.getInstructions(set, true)).isEmpty());
		assertTrue(takeN(10, listing.getInstructions(set, false)).isEmpty());

		Instruction i4005;
		Instruction i4007;
		Instruction i400a;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4005 = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
			i4007 = b.addInstruction(0, b.addr(0x4007), b.language, b.buf(0xf4, 0));
			i400a = b.addInstruction(0, b.addr(0x400a), b.language, b.buf(0xf4, 0));
			b.addData(0, b.addr(0x400c), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}

		assertEquals(List.of(i4005, i4007, i400a), takeN(10, listing.getInstructions(true)));
		assertEquals(List.of(i400a, i4007, i4005), takeN(10, listing.getInstructions(false)));
		assertEquals(List.of(i4007, i400a),
			takeN(10, listing.getInstructions(b.addr(0x4006), true)));
		assertEquals(List.of(i4007, i4005),
			takeN(10, listing.getInstructions(b.addr(0x4008), false)));

		assertEquals(List.of(i4005, i4007), takeN(10, listing.getInstructions(set, true)));
		assertEquals(List.of(i4007, i4005), takeN(10, listing.getInstructions(set, false)));
	}

	@Test
	public void testGetDataAt() throws CodeUnitInsertionException, InsufficientBytesException,
			UnknownInstructionException {
		assertUndefined(listing.getDataAt(b.addr(0x4000)));
		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getDataAt(b.addr(0x4000)));
		assertNull(listing.getDataAt(b.addr(0x4001)));
		assertNull(listing.getDataAt(b.addr(0x4002)));
		assertNull(listing.getDataAt(b.addr(0x4003)));
		assertUndefined(listing.getDataAt(b.addr(0x4004)));

		assertUndefined(listing.getDataAt(b.addr(0x4005)));
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertNull(listing.getDataAt(b.addr(0x4005)));
		assertNull(listing.getDataAt(b.addr(0x4006)));
		assertUndefined(listing.getDataAt(b.addr(0x4007)));
	}

	@Test
	public void testGetDataContaining() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		assertUndefined(listing.getDataContaining(b.addr(0x4000)));
		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getDataContaining(b.addr(0x4000)));
		assertEquals(d4000, listing.getDataContaining(b.addr(0x4001)));
		assertEquals(d4000, listing.getDataContaining(b.addr(0x4002)));
		assertEquals(d4000, listing.getDataContaining(b.addr(0x4003)));
		assertUndefined(listing.getDataContaining(b.addr(0x4004)));

		assertUndefined(listing.getDataContaining(b.addr(0x4005)));
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertNull(listing.getDataContaining(b.addr(0x4005)));
		assertNull(listing.getDataContaining(b.addr(0x4006)));
		assertUndefined(listing.getDataContaining(b.addr(0x4007)));
	}

	@Test
	public void testGetDataAfter() throws CodeUnitInsertionException, InsufficientBytesException,
			UnknownInstructionException {
		CodeUnit cu;

		assertUndefined(cu = listing.getDataAfter(b.addr(0x3fff)));
		assertEquals(b.addr(0x4000), cu.getAddress());
		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getDataAfter(b.addr(0x3fff)));
		assertUndefined(cu = listing.getDataAfter(b.addr(0x4000)));
		assertEquals(b.addr(0x4004), cu.getAddress());

		assertUndefined(cu = listing.getDataAfter(b.addr(0x4004)));
		assertEquals(b.addr(0x4005), cu.getAddress());
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertUndefined(cu = listing.getDataAfter(b.addr(0x4004)));
		assertEquals(b.addr(0x4007), cu.getAddress());
	}

	@Test
	public void testGetDataBefore() throws CodeUnitInsertionException, InsufficientBytesException,
			UnknownInstructionException {
		CodeUnit cu;

		assertUndefined(cu = listing.getDataBefore(b.addr(0x4001)));
		assertEquals(b.addr(0x4000), cu.getAddress());
		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getDataBefore(b.addr(0x4001)));
		assertUndefined(cu = listing.getDataBefore(b.addr(0x4000)));
		assertEquals(b.addr(0x3fff), cu.getAddress());

		assertUndefined(cu = listing.getDataBefore(b.addr(0x4006)));
		assertEquals(b.addr(0x4005), cu.getAddress());
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertUndefined(cu = listing.getDataBefore(b.addr(0x4007)));
		assertEquals(b.addr(0x4004), cu.getAddress());
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
			assertEquals(b.addr(i), cu.getAddress());
		}

		sample = takeN(10, listing.getData(false));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(b.addr(-1 - i), cu.getAddress());
		}

		sample = takeN(10, listing.getData(b.addr(0x3fff), true));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(b.addr(0x3fff + i), cu.getAddress());
		}

		sample = takeN(10, listing.getData(b.addr(0x4008), false));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(b.addr(0x4008 - i), cu.getAddress());
		}

		set = new AddressSet();
		set.add(b.addr(0x3ffe));
		set.add(b.range(0x4000, 0x4003));
		set.add(b.addr(0x4005)); // Range only restricts start addresses
		set.add(b.range(0x4007, 0x4008));
		sample = takeN(10, listing.getData(set, true));
		assertEquals(8, sample.size());
		assertEquals(b.addr(0x3ffe), sample.get(0).getAddress());
		assertEquals(b.addr(0x4000), sample.get(1).getAddress());
		assertEquals(b.addr(0x4001), sample.get(2).getAddress());
		assertEquals(b.addr(0x4002), sample.get(3).getAddress());
		assertEquals(b.addr(0x4003), sample.get(4).getAddress());
		assertEquals(b.addr(0x4005), sample.get(5).getAddress());
		assertEquals(b.addr(0x4007), sample.get(6).getAddress());
		assertEquals(b.addr(0x4008), sample.get(7).getAddress());

		sample = takeN(10, listing.getData(set, false));
		assertEquals(8, sample.size());
		assertEquals(b.addr(0x4008), sample.get(0).getAddress());
		assertEquals(b.addr(0x4007), sample.get(1).getAddress());
		assertEquals(b.addr(0x4005), sample.get(2).getAddress());
		assertEquals(b.addr(0x4003), sample.get(3).getAddress());
		assertEquals(b.addr(0x4002), sample.get(4).getAddress());
		assertEquals(b.addr(0x4001), sample.get(5).getAddress());
		assertEquals(b.addr(0x4000), sample.get(6).getAddress());
		assertEquals(b.addr(0x3ffe), sample.get(7).getAddress());

		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
			b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}

		sample = takeN(10, listing.getData(true));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(b.addr(i), cu.getAddress());
		}

		sample = takeN(10, listing.getData(false));
		assertEquals(10, sample.size());
		for (int i = 0; i < sample.size(); i++) {
			CodeUnit cu = sample.get(i);
			assertUndefined(cu);
			assertEquals(b.addr(-1 - i), cu.getAddress());
		}

		sample = takeN(4, listing.getData(b.addr(0x3fff), true));
		assertEquals(4, sample.size());
		assertUndefined(sample.get(0));
		assertEquals(b.addr(0x3fff), sample.get(0).getAddress());
		assertEquals(d4000, sample.get(1));
		assertUndefined(sample.get(2));
		assertEquals(b.addr(0x4004), sample.get(2).getAddress());
		assertUndefined(sample.get(3));
		assertEquals(b.addr(0x4007), sample.get(3).getAddress());

		sample = takeN(4, listing.getData(b.addr(0x4007), false));
		assertEquals(4, sample.size());
		assertUndefined(sample.get(0));
		assertEquals(b.addr(0x4007), sample.get(0).getAddress());
		assertUndefined(sample.get(1));
		assertEquals(b.addr(0x4004), sample.get(1).getAddress());
		assertEquals(d4000, sample.get(2));
		assertUndefined(sample.get(3));
		assertEquals(b.addr(0x3fff), sample.get(3).getAddress());

		sample = takeN(10, listing.getData(set, true));
		assertEquals(4, sample.size());
		assertEquals(b.addr(0x3ffe), sample.get(0).getAddress());
		assertEquals(d4000, sample.get(1));
		assertEquals(b.addr(0x4007), sample.get(2).getAddress());
		assertEquals(b.addr(0x4008), sample.get(3).getAddress());

		sample = takeN(10, listing.getData(set, false));
		assertEquals(4, sample.size());
		assertEquals(b.addr(0x4008), sample.get(0).getAddress());
		assertEquals(b.addr(0x4007), sample.get(1).getAddress());
		assertEquals(d4000, sample.get(2));
		assertEquals(b.addr(0x3ffe), sample.get(3).getAddress());
	}

	@Test
	public void testGetDefinedDataAt() throws CodeUnitInsertionException {
		assertNull(listing.getDefinedDataAt(b.addr(0x4000)));
		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getDefinedDataAt(b.addr(0x4000)));
		assertNull(listing.getDefinedDataAt(b.addr(0x4001)));
		assertNull(listing.getDefinedDataAt(b.addr(0x4002)));
		assertNull(listing.getDefinedDataAt(b.addr(0x4003)));
		assertNull(listing.getDefinedDataAt(b.addr(0x4004)));
		assertNull(listing.getDefinedDataAt(b.addr(0x4005)));
	}

	@Test
	public void testGetDefinedDataContaining() throws CodeUnitInsertionException {
		assertNull(listing.getDefinedDataContaining(b.addr(0x4005)));
		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getDefinedDataContaining(b.addr(0x4000)));
		assertEquals(d4000, listing.getDefinedDataContaining(b.addr(0x4001)));
		assertEquals(d4000, listing.getDefinedDataContaining(b.addr(0x4002)));
		assertEquals(d4000, listing.getDefinedDataContaining(b.addr(0x4003)));
		assertNull(listing.getDefinedDataContaining(b.addr(0x4004)));
	}

	@Test
	public void testGetDefinedDataAfter() throws CodeUnitInsertionException {
		assertNull(listing.getDefinedDataAfter(b.addr(0x4000)));
		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getDefinedDataAfter(b.addr(0x3fff)));
		assertNull(listing.getDefinedDataAfter(b.addr(0x4000)));
	}

	@Test
	public void testGetDefinedDataBefore() throws CodeUnitInsertionException {
		assertNull(listing.getDefinedDataBefore(b.addr(0x4004)));
		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getDefinedDataBefore(b.addr(0x4001)));
		assertNull(listing.getDefinedDataBefore(b.addr(0x4000)));
	}

	@Test
	public void testGetDefinedData() throws InsufficientBytesException, UnknownInstructionException,
			CodeUnitInsertionException {
		AddressSet set;

		assertTrue(takeN(10, listing.getDefinedData(true)).isEmpty());
		assertTrue(takeN(10, listing.getDefinedData(false)).isEmpty());
		assertTrue(takeN(10, listing.getDefinedData(b.addr(0x3fff), true)).isEmpty());
		assertTrue(takeN(10, listing.getDefinedData(b.addr(0x4009), false)).isEmpty());

		set = new AddressSet();
		set.add(b.addr(0x3ffe));
		set.add(b.range(0x4000, 0x4002));
		set.add(b.addr(0x4004));
		set.add(b.range(0x4007, 0x4008));
		assertTrue(takeN(10, listing.getDefinedData(set, true)).isEmpty());
		assertTrue(takeN(10, listing.getDefinedData(set, false)).isEmpty());

		Data d4000;
		Data d4004;
		Data d400a;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(0, 1, 2, 3));
			d4004 = b.addData(0, b.addr(0x4004), Undefined4DataType.dataType, b.buf(5, 6, 7, 8));
			d400a =
				b.addData(0, b.addr(0x400a), Undefined4DataType.dataType, b.buf(10, 11, 12, 13));
			b.addInstruction(0, b.addr(0x400e), b.language, b.buf(0xf4, 0));
		}

		assertEquals(List.of(d4000, d4004, d400a), takeN(10, listing.getDefinedData(true)));
		assertEquals(List.of(d400a, d4004, d4000), takeN(10, listing.getDefinedData(false)));
		assertEquals(List.of(d4004, d400a),
			takeN(10, listing.getDefinedData(b.addr(0x4004), true)));
		assertEquals(List.of(d4004, d4000),
			takeN(10, listing.getDefinedData(b.addr(0x4004), false)));

		assertEquals(List.of(d4000, d4004), takeN(10, listing.getDefinedData(set, true)));
		assertEquals(List.of(d4004, d4000), takeN(10, listing.getDefinedData(set, false)));
	}

	@Test
	public void testGetUndefinedDataAt() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		assertUndefined(listing.getUndefinedDataAt(b.addr(0x4000)));
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertNull(listing.getUndefinedDataAt(b.addr(0x4000)));
		assertNull(listing.getUndefinedDataAt(b.addr(0x4001)));
		assertNull(listing.getUndefinedDataAt(b.addr(0x4002)));
		assertNull(listing.getUndefinedDataAt(b.addr(0x4003)));
		assertUndefined(listing.getUndefinedDataAt(b.addr(0x4004)));

		assertUndefined(listing.getUndefinedDataAt(b.addr(0x4005)));
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertNull(listing.getUndefinedDataAt(b.addr(0x4005)));
		assertNull(listing.getUndefinedDataAt(b.addr(0x4006)));
		assertUndefined(listing.getUndefinedDataAt(b.addr(0x4007)));
	}

	@Test
	public void testGetUndefinedDataAfter() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		Data cu;

		assertUndefined(cu = listing.getUndefinedDataAfter(b.addr(0x3fff), TaskMonitor.DUMMY));
		assertEquals(b.addr(0x4000), cu.getAddress());
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertUndefined(cu = listing.getUndefinedDataAfter(b.addr(0x3fff), TaskMonitor.DUMMY));
		assertEquals(b.addr(0x4004), cu.getAddress());

		assertUndefined(cu = listing.getUndefinedDataAfter(b.addr(0x4004), TaskMonitor.DUMMY));
		assertEquals(b.addr(0x4005), cu.getAddress());
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertUndefined(cu = listing.getUndefinedDataAfter(b.addr(0x4004), TaskMonitor.DUMMY));
		assertEquals(b.addr(0x4007), cu.getAddress());
	}

	@Test
	public void testGetUndefinedDataBefore() throws CodeUnitInsertionException,
			InsufficientBytesException, UnknownInstructionException {
		Data cu;

		assertUndefined(cu = listing.getUndefinedDataBefore(b.addr(0x4001), TaskMonitor.DUMMY));
		assertEquals(b.addr(0x4000), cu.getAddress());
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertUndefined(cu = listing.getUndefinedDataBefore(b.addr(0x4004), TaskMonitor.DUMMY));
		assertEquals(b.addr(0x3fff), cu.getAddress());

		assertUndefined(cu = listing.getUndefinedDataBefore(b.addr(0x4006), TaskMonitor.DUMMY));
		assertEquals(b.addr(0x4005), cu.getAddress());
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertUndefined(cu = listing.getUndefinedDataBefore(b.addr(0x4007), TaskMonitor.DUMMY));
		assertEquals(b.addr(0x4004), cu.getAddress());
	}

	@Test
	public void testGetFirstUndefinedData() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
			b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		Data cu;

		assertUndefined(
			cu = listing.getFirstUndefinedData(b.set(b.range(0x3fff)), TaskMonitor.DUMMY));
		assertEquals(b.addr(0x3fff), cu.getAddress());
		assertUndefined(cu = listing.getFirstUndefinedData(
			b.set(b.range(0x4000, 0x4002), b.range(0x4005, 0x400a)), TaskMonitor.DUMMY));
		assertEquals(b.addr(0x4007), cu.getAddress());
	}

	@Test
	@Ignore("TODO")
	public void testGetUndefinedRanges() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException, CancelledException {
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
			b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}

		TODO(); // Should I expect OTHER ranges in the undefined set?
		assertEquals(b.set(b.range(0, 0x3fff), b.range(0x4004), b.range(0x4007, -1)),
			listing.getUndefinedRanges(
				view.getAddressFactory().getAddressSet(), false, TaskMonitor.DUMMY));
	}

	@Test
	public void testGetDefinedCodeUnitAfter() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		assertNull(listing.getDefinedCodeUnitAfter(b.addr(0x3fff)));
		Instruction i4005;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4005 = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertEquals(i4005, listing.getDefinedCodeUnitAfter(b.addr(0x3fff)));
		assertNull(listing.getDefinedCodeUnitAfter(b.addr(0x4005)));
		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getDefinedCodeUnitAfter(b.addr(0x3fff)));
		assertEquals(i4005, listing.getDefinedCodeUnitAfter(b.addr(0x4000)));
	}

	@Test
	public void testGetDefinedCodeUnitBefore() throws InsufficientBytesException,
			UnknownInstructionException, CodeUnitInsertionException {
		assertNull(listing.getDefinedCodeUnitBefore(b.addr(0x4006)));
		Data d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), Undefined4DataType.dataType, b.buf(1, 2, 3, 4));
		}
		assertEquals(d4000, listing.getDefinedCodeUnitBefore(b.addr(0x4006)));
		assertNull(listing.getDefinedCodeUnitBefore(b.addr(0x4000)));
		Instruction i4005;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4005 = b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
		}
		assertEquals(i4005, listing.getDefinedCodeUnitBefore(b.addr(0x4006)));
		assertEquals(d4000, listing.getDefinedCodeUnitBefore(b.addr(0x4005)));
	}
}
