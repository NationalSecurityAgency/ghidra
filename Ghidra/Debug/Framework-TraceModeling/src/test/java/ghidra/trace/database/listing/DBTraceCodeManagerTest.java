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
package ghidra.trace.database.listing;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.junit.*;

import com.google.common.collect.Range;

import ghidra.lifecycle.Unfinished;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.context.DBTraceRegisterContextManager;
import ghidra.trace.database.language.*;
import ghidra.trace.database.stack.DBTraceStack;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.listing.*;
import ghidra.util.IntersectionAddressSetView;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class DBTraceCodeManagerTest extends AbstractGhidraHeadlessIntegrationTest
		implements Unfinished {

	/**
	 * A dorked string type which ignores the maxLength parameter
	 */
	public static class NoMaxStringDataType extends TerminatedStringDataType {
		@SuppressWarnings("hiding")
		public static final NoMaxStringDataType dataType = new NoMaxStringDataType();

		public NoMaxStringDataType() {
			super();
		}

		public NoMaxStringDataType(DataTypeManager dtm) {
			super(dtm);
		}

		@Override
		public boolean canSpecifyLength() {
			return false;
		}

		@Override
		public int getLength(MemBuffer buf, int maxLength) {
			return super.getLength(buf, Integer.MAX_VALUE);
		}

		@Override
		public DataType clone(DataTypeManager dtm) {
			if (dtm == getDataTypeManager()) {
				return this;
			}
			return new NoMaxStringDataType(dtm);
		}
	}

	ToyDBTraceBuilder b;
	DBTraceCodeManager manager;

	protected static void assertUndefined(TraceCodeUnit cu) {
		assertTrue(cu instanceof TraceData);
		TraceData data = (TraceData) cu;
		assertEquals(DataType.DEFAULT, data.getDataType());
		assertTrue(cu instanceof UndefinedDBTraceData);
		assertFalse(data.isDefined());
	}

	@Before
	public void setUpTraceCodeManagerTest() throws IOException {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:harvard");
		manager = b.trace.getCodeManager();
	}

	@After
	public void tearDownTraceCodeManagerTest() {
		b.close();
	}

	@Test
	public void testAddDefinedData() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
		}
	}

	@Test
	public void testAddDataPrecedingBytesChanged() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			b.trace.getMemoryManager().putBytes(10, b.addr(0x4001), b.buf(0xaa));
			TraceData d4000 =
				b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			assertEquals(Range.closed(0L, 9L), d4000.getLifespan());
		}
	}

	@Test
	public void testPutBytesTruncatesDynamicData() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceData d4000 =
				b.addData(0, b.addr(0x4000), NoMaxStringDataType.dataType, b.buf("Hello"));
			assertEquals(b.addr(0x4005), d4000.getMaxAddress());
			assertEquals(Range.atLeast(0L), d4000.getLifespan());
			b.trace.getMemoryManager().putBytes(10, b.addr(0x4005), b.buf(", World!"));
			assertEquals(Range.closed(0L, 9L), d4000.getLifespan());
			assertNull(b.trace.getCodeManager().definedData().getContaining(10, b.addr(0x4005)));
		}
	}

	@Test
	public void testPutBytesSplitsDynamicDataSameLength() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceData d0at4000 =
				b.addData(0, b.addr(0x4000), NoMaxStringDataType.dataType, b.buf("Hello"));
			assertEquals(b.addr(0x4005), d0at4000.getMaxAddress());
			assertEquals(Range.atLeast(0L), d0at4000.getLifespan());
			b.trace.getMemoryManager().putBytes(10, b.addr(0x4000), b.buf("World"));
			assertEquals(Range.closed(0L, 9L), d0at4000.getLifespan());
			TraceData d10at4000 =
				b.trace.getCodeManager().definedData().getContaining(10, b.addr(0x4000));
			assertEquals(b.addr(0x4005), d10at4000.getMaxAddress());
			assertEquals(Range.atLeast(10L), d10at4000.getLifespan());
		}
	}

	@Test
	public void testPutBytesSplitsStaticData() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceData d0at4000 =
				b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			assertEquals(Range.atLeast(0L), d0at4000.getLifespan());
			b.trace.getMemoryManager().putBytes(10, b.addr(0x4000), b.buf(5, 6, 7, 8));
			assertEquals(Range.closed(0L, 9L), d0at4000.getLifespan());
			TraceData d10at4000 =
				b.trace.getCodeManager().definedData().getContaining(10, b.addr(0x4000));
			assertEquals(Range.atLeast(10L), d10at4000.getLifespan());
			assertEquals(new Scalar(32, 0x01020304), d0at4000.getValue());
			assertEquals(new Scalar(32, 0x05060708), d10at4000.getValue());
		}
	}

	@Test
	public void testPutBytesDeletesDynamicData() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceData d4000 =
				b.addData(0, b.addr(0x4000), NoMaxStringDataType.dataType, b.buf("Hello"));
			assertEquals(b.addr(0x4005), d4000.getMaxAddress());
			assertEquals(Range.atLeast(0L), d4000.getLifespan());
			b.trace.getMemoryManager().putBytes(0, b.addr(0x4005), b.buf(", World!"));
			assertNull(b.trace.getCodeManager().definedData().getContaining(0, b.addr(0x4000)));
		}
	}

	@Test
	public void testAddInstruction() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
		}
	}

	@Test
	public void testAddInstructionPrecedingBytesChanged() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			b.trace.getMemoryManager().putBytes(10, b.addr(0x4001), b.buf(0xaa));
			TraceInstruction i4000 =
				b.addInstruction(0, b.addr(0x4000), b.language, b.buf(0xf4, 0));
			assertEquals(Range.closed(0L, 9L), i4000.getLifespan());
		}
	}

	@Test
	public void testPutBytesTruncatesInstruction() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceInstruction i4000 =
				b.addInstruction(0, b.addr(0x4000), b.language, b.buf(0xf4, 0));
			assertEquals(b.addr(0x4001), i4000.getMaxAddress());
			assertEquals(Range.atLeast(0L), i4000.getLifespan());
			b.trace.getMemoryManager().putBytes(10, b.addr(0x4001), b.buf(1));
			assertEquals(Range.closed(0L, 9L), i4000.getLifespan());
			assertNull(b.trace.getCodeManager().instructions().getContaining(10, b.addr(0x4000)));
		}
	}

	@Test
	public void testPutBytesDeletesInstruction() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceInstruction i4000 =
				b.addInstruction(0, b.addr(0x4000), b.language, b.buf(0xf4, 0));
			assertEquals(b.addr(0x4001), i4000.getMaxAddress());
			assertEquals(Range.atLeast(0L), i4000.getLifespan());
			b.trace.getMemoryManager().putBytes(0, b.addr(0x4001), b.buf(1));
			assertNull(b.trace.getCodeManager().instructions().getContaining(0, b.addr(0x4000)));
		}
	}

	@Test
	public void testAddUndefinedData() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addData(0, b.addr(0x4000), DefaultDataType.dataType, b.buf(1));
			DBTraceCodeSpace code = manager.getCodeSpace(b.language.getDefaultSpace(), true);
			assertTrue(code.definedData().mapSpace.isEmpty());
		}
	}

	@Test
	public void testOverlapErrors() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));

			try {
				b.addData(1, b.addr(0x4001), ByteDataType.dataType, 1);
				fail();
			}
			catch (CodeUnitInsertionException e) {
				// pass
			}

			try {
				b.addInstruction(1, b.addr(0x4001), b.language);
				fail();
			}
			catch (CodeUnitInsertionException e) {
				// pass
			}

			b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));

			try {
				b.addData(1, b.addr(0x4005), ByteDataType.dataType, 1);
				fail();
			}
			catch (CodeUnitInsertionException e) {
				// pass
			}

			try {
				b.addInstruction(1, b.addr(0x4005), b.language);
			}
			catch (CodeUnitInsertionException e) {
				// pass
			}
		}
	}

	protected void assertAllNullFunc(Function<TraceBaseCodeUnitsView<?>, TraceCodeUnit> func) {
		assertNull(func.apply(manager.codeUnits()));
		assertNull(func.apply(manager.data()));
		assertNull(func.apply(manager.definedUnits()));
		assertNull(func.apply(manager.definedData()));
		assertNull(func.apply(manager.instructions()));
		assertNull(func.apply(manager.undefinedData()));
	}

	protected void assertUndefinedFunc(Function<TraceBaseCodeUnitsView<?>, TraceCodeUnit> func) {
		assertUndefined(func.apply(manager.codeUnits()));
		assertUndefined(func.apply(manager.data()));
		assertNull(func.apply(manager.definedUnits()));
		assertNull(func.apply(manager.definedData()));
		assertNull(func.apply(manager.instructions()));
		assertUndefined(func.apply(manager.undefinedData()));
	}

	protected void assertDataFunc(TraceData data,
			Function<TraceBaseCodeUnitsView<?>, TraceCodeUnit> func) {
		assertEquals(data, func.apply(manager.codeUnits()));
		assertEquals(data, func.apply(manager.data()));
		assertEquals(data, func.apply(manager.definedUnits()));
		assertEquals(data, func.apply(manager.definedData()));
		assertNull(func.apply(manager.instructions()));
		assertNull(func.apply(manager.undefinedData()));
	}

	protected void assertInstructionFunc(TraceInstruction ins,
			Function<TraceBaseCodeUnitsView<?>, TraceCodeUnit> func) {
		assertEquals(ins, func.apply(manager.codeUnits()));
		assertNull(func.apply(manager.data()));
		assertEquals(ins, func.apply(manager.definedUnits()));
		assertNull(func.apply(manager.definedData()));
		assertEquals(ins, func.apply(manager.instructions()));
		assertNull(func.apply(manager.undefinedData()));
	}

	@Test
	public void testGetAt() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			assertUndefinedFunc(v -> v.getAt(0, b.addr(0x4000)));
			TraceData d4000 =
				b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			assertDataFunc(d4000, v -> v.getAt(0, b.addr(0x4000)));
			assertDataFunc(d4000, v -> v.getAt(9, b.addr(0x4000)));
			assertUndefinedFunc(v -> v.getAt(10, b.addr(0x4000)));
			assertAllNullFunc(v -> v.getAt(0, b.addr(0x4001)));
			assertAllNullFunc(v -> v.getAt(0, b.addr(0x4002)));
			assertAllNullFunc(v -> v.getAt(0, b.addr(0x4003)));
			assertUndefinedFunc(v -> v.getAt(0, b.addr(0x4004)));
			assertAllNullFunc(v -> v.getAt(9, b.addr(0x4001)));
			assertAllNullFunc(v -> v.getAt(9, b.addr(0x4002)));
			assertAllNullFunc(v -> v.getAt(9, b.addr(0x4003)));
			assertUndefinedFunc(v -> v.getAt(9, b.addr(0x4004)));

			TraceInstruction i4005 =
				b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
			i4005.setEndSnap(5);
			assertUndefinedFunc(v -> v.getAt(0, b.addr(0x4004)));
			assertInstructionFunc(i4005, v -> v.getAt(0, b.addr(0x4005)));
			assertInstructionFunc(i4005, v -> v.getAt(5, b.addr(0x4005)));
			assertUndefinedFunc(v -> v.getAt(6, b.addr(0x4005)));
			assertAllNullFunc(v -> v.getAt(0, b.addr(0x4006)));
			assertAllNullFunc(v -> v.getAt(5, b.addr(0x4006)));
			assertUndefinedFunc(v -> v.getAt(0, b.addr(0x4007)));
		}
	}

	@Test
	public void testGetContaining() throws CodeUnitInsertionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			assertUndefinedFunc(v -> v.getContaining(0, b.addr(0x4000)));
			TraceData d4000 =
				b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			assertUndefinedFunc(v -> v.getContaining(0, b.addr(0x3fff)));

			assertDataFunc(d4000, v -> v.getContaining(0, b.addr(0x4000)));
			assertDataFunc(d4000, v -> v.getContaining(9, b.addr(0x4000)));
			assertUndefinedFunc(v -> v.getContaining(10, b.addr(0x4000)));
			assertDataFunc(d4000, v -> v.getContaining(0, b.addr(0x4001)));
			assertDataFunc(d4000, v -> v.getContaining(0, b.addr(0x4002)));
			assertDataFunc(d4000, v -> v.getContaining(0, b.addr(0x4003)));
			assertUndefinedFunc(v -> v.getContaining(0, b.addr(0x4004)));
			assertDataFunc(d4000, v -> v.getContaining(9, b.addr(0x4001)));
			assertDataFunc(d4000, v -> v.getContaining(9, b.addr(0x4002)));
			assertDataFunc(d4000, v -> v.getContaining(9, b.addr(0x4003)));
			assertUndefinedFunc(v -> v.getContaining(9, b.addr(0x4004)));

			TraceInstruction i4005 =
				b.addInstruction(0, b.addr(0x4005), b.language, b.buf(0xf4, 0));
			i4005.setEndSnap(5);
			assertUndefinedFunc(v -> v.getContaining(0, b.addr(0x4004)));

			assertInstructionFunc(i4005, v -> v.getContaining(0, b.addr(0x4005)));
			assertInstructionFunc(i4005, v -> v.getContaining(5, b.addr(0x4005)));
			assertUndefinedFunc(v -> v.getContaining(6, b.addr(0x4005)));
			assertInstructionFunc(i4005, v -> v.getContaining(0, b.addr(0x4006)));
			assertUndefinedFunc(v -> v.getContaining(0, b.addr(0x4007)));
			assertInstructionFunc(i4005, v -> v.getContaining(5, b.addr(0x4006)));
			assertUndefinedFunc(v -> v.getContaining(5, b.addr(0x4007)));
		}
	}

	@Test
	public void testGetRelativesEmpty() throws CodeUnitInsertionException {
		TraceCodeUnit u3fff = manager.codeUnits().getBefore(0, b.addr(0x4000));
		assertUndefined(u3fff);
		assertEquals(b.addr(0x3fff), u3fff.getAddress());
		assertEquals(u3fff, manager.data().getBefore(0, b.addr(0x4000)));
		assertEquals(u3fff, manager.undefinedData().getBefore(0, b.addr(0x4000)));
		assertNull(manager.definedUnits().getBefore(0, b.addr(0x4000)));
		assertNull(manager.instructions().getBefore(0, b.addr(0x4000)));
		assertNull(manager.definedData().getBefore(0, b.addr(0x4000)));

		TraceCodeUnit u4000 = manager.codeUnits().getFloor(0, b.addr(0x4000));
		assertUndefined(u4000);
		assertEquals(b.addr(0x4000), u4000.getAddress());
		assertEquals(u4000, manager.data().getFloor(0, b.addr(0x4000)));
		assertEquals(u4000, manager.undefinedData().getFloor(0, b.addr(0x4000)));
		assertNull(manager.definedUnits().getFloor(0, b.addr(0x4000)));
		assertNull(manager.instructions().getFloor(0, b.addr(0x4000)));
		assertNull(manager.definedData().getFloor(0, b.addr(0x4000)));

		assertEquals(u4000, manager.codeUnits().getCeiling(0, b.addr(0x4000)));
		assertEquals(u4000, manager.data().getCeiling(0, b.addr(0x4000)));
		assertEquals(u4000, manager.undefinedData().getCeiling(0, b.addr(0x4000)));
		assertNull(manager.definedUnits().getCeiling(0, b.addr(0x4000)));
		assertNull(manager.instructions().getCeiling(0, b.addr(0x4000)));
		assertNull(manager.definedData().getCeiling(0, b.addr(0x4000)));

		TraceCodeUnit u4001 = manager.codeUnits().getAfter(0, b.addr(0x4000));
		assertUndefined(u4001);
		assertEquals(b.addr(0x4001), u4001.getAddress());
		assertEquals(u4001, manager.data().getAfter(0, b.addr(0x4000)));
		assertEquals(u4001, manager.undefinedData().getAfter(0, b.addr(0x4000)));
		assertNull(manager.definedUnits().getAfter(0, b.addr(0x4000)));
		assertNull(manager.instructions().getAfter(0, b.addr(0x4000)));
		assertNull(manager.definedData().getAfter(0, b.addr(0x4000)));
	}

	protected static void assertUndefinedWithAddr(Address address, TraceCodeUnit cu) {
		assertUndefined(cu);
		assertEquals(address, cu.getAddress());
	}

	@Test
	public void testGetBefore() throws CodeUnitInsertionException {
		TraceData d4000;
		TraceData d4004;
		TraceInstruction i4008;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			d4004 = b.addData(0, b.addr(0x4004), IntegerDataType.dataType, b.buf(5, 6, 7, 8));
			d4004.setEndSnap(5);
			i4008 = b.addInstruction(0, b.addr(0x4008), b.language, b.buf(0xf4, 0));
			i4008.setEndSnap(9);
		}

		assertUndefinedWithAddr(b.addr(0x3fff), manager.codeUnits().getBefore(0, b.addr(0x4000)));
		assertUndefinedWithAddr(b.addr(0x3fff), manager.data().getBefore(0, b.addr(0x4000)));
		assertNull(manager.definedUnits().getBefore(0, b.addr(0x4000)));
		assertNull(manager.instructions().getBefore(0, b.addr(0x4000)));
		assertNull(manager.definedData().getBefore(0, b.addr(0x4000)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getBefore(0, b.addr(0x4000)));

		assertEquals(d4000, manager.codeUnits().getBefore(0, b.addr(0x4001)));
		assertEquals(d4000, manager.data().getBefore(0, b.addr(0x4001)));
		assertEquals(d4000, manager.definedUnits().getBefore(0, b.addr(0x4001)));
		assertNull(manager.instructions().getBefore(0, b.addr(0x4001)));
		assertEquals(d4000, manager.definedData().getBefore(0, b.addr(0x4001)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getBefore(0, b.addr(0x4001)));

		assertEquals(d4000, manager.codeUnits().getBefore(0, b.addr(0x4002)));
		assertEquals(d4000, manager.data().getBefore(0, b.addr(0x4002)));
		assertEquals(d4000, manager.definedUnits().getBefore(0, b.addr(0x4002)));
		assertNull(manager.instructions().getBefore(0, b.addr(0x4002)));
		assertEquals(d4000, manager.definedData().getBefore(0, b.addr(0x4002)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getBefore(0, b.addr(0x4002)));

		assertEquals(d4000, manager.codeUnits().getBefore(0, b.addr(0x4003)));
		assertEquals(d4000, manager.data().getBefore(0, b.addr(0x4003)));
		assertEquals(d4000, manager.definedUnits().getBefore(0, b.addr(0x4003)));
		assertNull(manager.instructions().getBefore(0, b.addr(0x4003)));
		assertEquals(d4000, manager.definedData().getBefore(0, b.addr(0x4003)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getBefore(0, b.addr(0x4003)));

		assertEquals(d4000, manager.codeUnits().getBefore(0, b.addr(0x4004)));
		assertEquals(d4000, manager.data().getBefore(0, b.addr(0x4004)));
		assertEquals(d4000, manager.definedUnits().getBefore(0, b.addr(0x4004)));
		assertNull(manager.instructions().getBefore(0, b.addr(0x4004)));
		assertEquals(d4000, manager.definedData().getBefore(0, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getBefore(0, b.addr(0x4004)));

		assertEquals(d4004, manager.codeUnits().getBefore(0, b.addr(0x4005)));
		assertEquals(d4004, manager.data().getBefore(0, b.addr(0x4005)));
		assertEquals(d4004, manager.definedUnits().getBefore(0, b.addr(0x4005)));
		assertNull(manager.instructions().getBefore(0, b.addr(0x4005)));
		assertEquals(d4004, manager.definedData().getBefore(0, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getBefore(0, b.addr(0x4005)));

		assertEquals(d4004, manager.codeUnits().getBefore(0, b.addr(0x4006)));
		assertEquals(d4004, manager.data().getBefore(0, b.addr(0x4006)));
		assertEquals(d4004, manager.definedUnits().getBefore(0, b.addr(0x4006)));
		assertNull(manager.instructions().getBefore(0, b.addr(0x4006)));
		assertEquals(d4004, manager.definedData().getBefore(0, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getBefore(0, b.addr(0x4006)));

		assertEquals(d4004, manager.codeUnits().getBefore(0, b.addr(0x4007)));
		assertEquals(d4004, manager.data().getBefore(0, b.addr(0x4007)));
		assertEquals(d4004, manager.definedUnits().getBefore(0, b.addr(0x4007)));
		assertNull(manager.instructions().getBefore(0, b.addr(0x4007)));
		assertEquals(d4004, manager.definedData().getBefore(0, b.addr(0x4007)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getBefore(0, b.addr(0x4007)));

		assertEquals(d4004, manager.codeUnits().getBefore(0, b.addr(0x4008)));
		assertEquals(d4004, manager.data().getBefore(0, b.addr(0x4008)));
		assertEquals(d4004, manager.definedUnits().getBefore(0, b.addr(0x4008)));
		assertNull(manager.instructions().getBefore(0, b.addr(0x4008)));
		assertEquals(d4004, manager.definedData().getBefore(0, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getBefore(0, b.addr(0x4008)));

		assertEquals(i4008, manager.codeUnits().getBefore(0, b.addr(0x4009)));
		assertEquals(d4004, manager.data().getBefore(0, b.addr(0x4009)));
		assertEquals(i4008, manager.definedUnits().getBefore(0, b.addr(0x4009)));
		assertEquals(i4008, manager.instructions().getBefore(0, b.addr(0x4009)));
		assertEquals(d4004, manager.definedData().getBefore(0, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getBefore(0, b.addr(0x4009)));

		assertEquals(i4008, manager.codeUnits().getBefore(0, b.addr(0x400a)));
		assertEquals(d4004, manager.data().getBefore(0, b.addr(0x400a)));
		assertEquals(i4008, manager.definedUnits().getBefore(0, b.addr(0x400a)));
		assertEquals(i4008, manager.instructions().getBefore(0, b.addr(0x400a)));
		assertEquals(d4004, manager.definedData().getBefore(0, b.addr(0x400a)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getBefore(0, b.addr(0x400a)));

		// For the snap-6 tests, just check that the snap is heeded by view
		// Only check thoroughly the codeUnits view
		assertUndefinedWithAddr(b.addr(0x3fff), manager.codeUnits().getBefore(6, b.addr(0x4000)));
		assertEquals(d4000, manager.codeUnits().getBefore(6, b.addr(0x4001)));
		assertEquals(d4000, manager.codeUnits().getBefore(6, b.addr(0x4002)));
		assertEquals(d4000, manager.codeUnits().getBefore(6, b.addr(0x4003)));
		assertEquals(d4000, manager.codeUnits().getBefore(6, b.addr(0x4004)));

		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getBefore(6, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.data().getBefore(6, b.addr(0x4005)));
		assertEquals(d4000, manager.definedUnits().getBefore(6, b.addr(0x4005)));
		assertNull(manager.instructions().getBefore(6, b.addr(0x4005)));
		assertEquals(d4000, manager.definedData().getBefore(6, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x4004),
			manager.undefinedData().getBefore(6, b.addr(0x4005)));

		assertUndefinedWithAddr(b.addr(0x4005), manager.codeUnits().getBefore(6, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x4006), manager.codeUnits().getBefore(6, b.addr(0x4007)));
		assertUndefinedWithAddr(b.addr(0x4007), manager.codeUnits().getBefore(6, b.addr(0x4008)));
		assertEquals(i4008, manager.codeUnits().getBefore(6, b.addr(0x4009)));
		assertEquals(i4008, manager.codeUnits().getBefore(6, b.addr(0x400a)));

		assertUndefinedWithAddr(b.addr(0x3fff), manager.codeUnits().getBefore(10, b.addr(0x4000)));
		assertUndefinedWithAddr(b.addr(0x4000), manager.codeUnits().getBefore(10, b.addr(0x4001)));
		assertUndefinedWithAddr(b.addr(0x4001), manager.codeUnits().getBefore(10, b.addr(0x4002)));
		assertUndefinedWithAddr(b.addr(0x4002), manager.codeUnits().getBefore(10, b.addr(0x4003)));
		assertUndefinedWithAddr(b.addr(0x4003), manager.codeUnits().getBefore(10, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getBefore(10, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x4005), manager.codeUnits().getBefore(10, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x4006), manager.codeUnits().getBefore(10, b.addr(0x4007)));
		assertUndefinedWithAddr(b.addr(0x4007), manager.codeUnits().getBefore(10, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x4008), manager.codeUnits().getBefore(10, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x4009), manager.codeUnits().getBefore(10, b.addr(0x400a)));

		assertNull(manager.instructions().getBefore(10, b.addr(0x400a)));

		// Nothing exists before 0
		assertNull(manager.codeUnits().getBefore(0, b.addr(0x0000)));
	}

	@Test
	public void testGetFloor() throws CodeUnitInsertionException {
		TraceData d4000;
		TraceData d4004;
		TraceInstruction i4008;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			d4004 = b.addData(0, b.addr(0x4004), IntegerDataType.dataType, b.buf(5, 6, 7, 8));
			d4004.setEndSnap(5);
			i4008 = b.addInstruction(0, b.addr(0x4008), b.language, b.buf(0xf4, 0));
			i4008.setEndSnap(9);
		}

		assertEquals(d4000, manager.codeUnits().getFloor(0, b.addr(0x4000)));
		assertEquals(d4000, manager.data().getFloor(0, b.addr(0x4000)));
		assertEquals(d4000, manager.definedUnits().getFloor(0, b.addr(0x4000)));
		assertNull(manager.instructions().getFloor(0, b.addr(0x4000)));
		assertEquals(d4000, manager.definedData().getFloor(0, b.addr(0x4000)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getFloor(0, b.addr(0x4000)));

		assertEquals(d4000, manager.codeUnits().getFloor(0, b.addr(0x4001)));
		assertEquals(d4000, manager.data().getFloor(0, b.addr(0x4001)));
		assertEquals(d4000, manager.definedUnits().getFloor(0, b.addr(0x4001)));
		assertNull(manager.instructions().getFloor(0, b.addr(0x4001)));
		assertEquals(d4000, manager.definedData().getFloor(0, b.addr(0x4001)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getFloor(0, b.addr(0x4001)));

		assertEquals(d4000, manager.codeUnits().getFloor(0, b.addr(0x4002)));
		assertEquals(d4000, manager.data().getFloor(0, b.addr(0x4002)));
		assertEquals(d4000, manager.definedUnits().getFloor(0, b.addr(0x4002)));
		assertNull(manager.instructions().getFloor(0, b.addr(0x4002)));
		assertEquals(d4000, manager.definedData().getFloor(0, b.addr(0x4002)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getFloor(0, b.addr(0x4002)));

		assertEquals(d4000, manager.codeUnits().getFloor(0, b.addr(0x4003)));
		assertEquals(d4000, manager.data().getFloor(0, b.addr(0x4003)));
		assertEquals(d4000, manager.definedUnits().getFloor(0, b.addr(0x4003)));
		assertNull(manager.instructions().getFloor(0, b.addr(0x4003)));
		assertEquals(d4000, manager.definedData().getFloor(0, b.addr(0x4003)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getFloor(0, b.addr(0x4003)));

		assertEquals(d4004, manager.codeUnits().getFloor(0, b.addr(0x4004)));
		assertEquals(d4004, manager.data().getFloor(0, b.addr(0x4004)));
		assertEquals(d4004, manager.definedUnits().getFloor(0, b.addr(0x4004)));
		assertNull(manager.instructions().getFloor(0, b.addr(0x4004)));
		assertEquals(d4004, manager.definedData().getFloor(0, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getFloor(0, b.addr(0x4004)));

		assertEquals(d4004, manager.codeUnits().getFloor(0, b.addr(0x4005)));
		assertEquals(d4004, manager.data().getFloor(0, b.addr(0x4005)));
		assertEquals(d4004, manager.definedUnits().getFloor(0, b.addr(0x4005)));
		assertNull(manager.instructions().getFloor(0, b.addr(0x4005)));
		assertEquals(d4004, manager.definedData().getFloor(0, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getFloor(0, b.addr(0x4005)));

		assertEquals(d4004, manager.codeUnits().getFloor(0, b.addr(0x4006)));
		assertEquals(d4004, manager.data().getFloor(0, b.addr(0x4006)));
		assertEquals(d4004, manager.definedUnits().getFloor(0, b.addr(0x4006)));
		assertNull(manager.instructions().getFloor(0, b.addr(0x4006)));
		assertEquals(d4004, manager.definedData().getFloor(0, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getFloor(0, b.addr(0x4006)));

		assertEquals(d4004, manager.codeUnits().getFloor(0, b.addr(0x4007)));
		assertEquals(d4004, manager.data().getFloor(0, b.addr(0x4007)));
		assertEquals(d4004, manager.definedUnits().getFloor(0, b.addr(0x4007)));
		assertNull(manager.instructions().getFloor(0, b.addr(0x4007)));
		assertEquals(d4004, manager.definedData().getFloor(0, b.addr(0x4007)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getFloor(0, b.addr(0x4007)));

		assertEquals(i4008, manager.codeUnits().getFloor(0, b.addr(0x4008)));
		assertEquals(d4004, manager.data().getFloor(0, b.addr(0x4008)));
		assertEquals(i4008, manager.definedUnits().getFloor(0, b.addr(0x4008)));
		assertEquals(i4008, manager.instructions().getFloor(0, b.addr(0x4008)));
		assertEquals(d4004, manager.definedData().getFloor(0, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getFloor(0, b.addr(0x4008)));

		assertEquals(i4008, manager.codeUnits().getFloor(0, b.addr(0x4009)));
		assertEquals(d4004, manager.data().getFloor(0, b.addr(0x4009)));
		assertEquals(i4008, manager.definedUnits().getFloor(0, b.addr(0x4009)));
		assertEquals(i4008, manager.instructions().getFloor(0, b.addr(0x4009)));
		assertEquals(d4004, manager.definedData().getFloor(0, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getFloor(0, b.addr(0x4009)));

		assertUndefinedWithAddr(b.addr(0x400a), manager.codeUnits().getFloor(0, b.addr(0x400a)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.data().getFloor(0, b.addr(0x400a)));
		assertEquals(i4008, manager.definedUnits().getFloor(0, b.addr(0x400a)));
		assertEquals(i4008, manager.instructions().getFloor(0, b.addr(0x400a)));
		assertEquals(d4004, manager.definedData().getFloor(0, b.addr(0x400a)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getFloor(0, b.addr(0x400a)));

		// For the snap-6 tests, just check that the snap is heeded by view
		// Only check thoroughly the codeUnits view
		assertEquals(d4000, manager.codeUnits().getFloor(6, b.addr(0x4000)));
		assertEquals(d4000, manager.codeUnits().getFloor(6, b.addr(0x4001)));
		assertEquals(d4000, manager.codeUnits().getFloor(6, b.addr(0x4002)));
		assertEquals(d4000, manager.codeUnits().getFloor(6, b.addr(0x4003)));

		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getFloor(6, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.data().getFloor(6, b.addr(0x4004)));
		assertEquals(d4000, manager.definedUnits().getFloor(6, b.addr(0x4004)));
		assertNull(manager.instructions().getFloor(6, b.addr(0x4004)));
		assertEquals(d4000, manager.definedData().getFloor(6, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x4004),
			manager.undefinedData().getFloor(6, b.addr(0x4004)));

		assertUndefinedWithAddr(b.addr(0x4005), manager.codeUnits().getFloor(6, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x4006), manager.codeUnits().getFloor(6, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x4007), manager.codeUnits().getFloor(6, b.addr(0x4007)));
		assertEquals(i4008, manager.codeUnits().getFloor(6, b.addr(0x4008)));
		assertEquals(i4008, manager.codeUnits().getFloor(6, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.codeUnits().getFloor(6, b.addr(0x400a)));

		assertUndefinedWithAddr(b.addr(0x4000), manager.codeUnits().getFloor(10, b.addr(0x4000)));
		assertUndefinedWithAddr(b.addr(0x4001), manager.codeUnits().getFloor(10, b.addr(0x4001)));
		assertUndefinedWithAddr(b.addr(0x4002), manager.codeUnits().getFloor(10, b.addr(0x4002)));
		assertUndefinedWithAddr(b.addr(0x4003), manager.codeUnits().getFloor(10, b.addr(0x4003)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getFloor(10, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x4005), manager.codeUnits().getFloor(10, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x4006), manager.codeUnits().getFloor(10, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x4007), manager.codeUnits().getFloor(10, b.addr(0x4007)));
		assertUndefinedWithAddr(b.addr(0x4008), manager.codeUnits().getFloor(10, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x4009), manager.codeUnits().getFloor(10, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.codeUnits().getFloor(10, b.addr(0x400a)));

		assertNull(manager.instructions().getFloor(10, b.addr(0x400a)));
	}

	@Test
	public void testGetCeiling() throws CodeUnitInsertionException {
		TraceData d4000;
		TraceData d4004;
		TraceInstruction i4008;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			d4004 = b.addData(0, b.addr(0x4004), IntegerDataType.dataType, b.buf(5, 6, 7, 8));
			d4004.setEndSnap(5);
			i4008 = b.addInstruction(0, b.addr(0x4008), b.language, b.buf(0xf4, 0));
			i4008.setEndSnap(9);
		}

		assertUndefinedWithAddr(b.addr(0x3fff), manager.codeUnits().getCeiling(0, b.addr(0x3fff)));
		assertUndefinedWithAddr(b.addr(0x3fff), manager.data().getCeiling(0, b.addr(0x3fff)));
		assertEquals(d4000, manager.definedUnits().getCeiling(0, b.addr(0x3fff)));
		assertEquals(i4008, manager.instructions().getCeiling(0, b.addr(0x3fff)));
		assertEquals(d4000, manager.definedData().getCeiling(0, b.addr(0x3fff)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			manager.undefinedData().getCeiling(0, b.addr(0x3fff)));

		assertEquals(d4000, manager.codeUnits().getCeiling(0, b.addr(0x4000)));
		assertEquals(d4000, manager.data().getCeiling(0, b.addr(0x4000)));
		assertEquals(d4000, manager.definedUnits().getCeiling(0, b.addr(0x4000)));
		assertEquals(i4008, manager.instructions().getCeiling(0, b.addr(0x4000)));
		assertEquals(d4000, manager.definedData().getCeiling(0, b.addr(0x4000)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getCeiling(0, b.addr(0x4000)));

		assertEquals(d4004, manager.codeUnits().getCeiling(0, b.addr(0x4001)));
		assertEquals(d4004, manager.data().getCeiling(0, b.addr(0x4001)));
		assertEquals(d4004, manager.definedUnits().getCeiling(0, b.addr(0x4001)));
		assertEquals(i4008, manager.instructions().getCeiling(0, b.addr(0x4001)));
		assertEquals(d4004, manager.definedData().getCeiling(0, b.addr(0x4001)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getCeiling(0, b.addr(0x4001)));

		assertEquals(d4004, manager.codeUnits().getCeiling(0, b.addr(0x4002)));
		assertEquals(d4004, manager.data().getCeiling(0, b.addr(0x4002)));
		assertEquals(d4004, manager.definedUnits().getCeiling(0, b.addr(0x4002)));
		assertEquals(i4008, manager.instructions().getCeiling(0, b.addr(0x4002)));
		assertEquals(d4004, manager.definedData().getCeiling(0, b.addr(0x4002)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getCeiling(0, b.addr(0x4002)));

		assertEquals(d4004, manager.codeUnits().getCeiling(0, b.addr(0x4003)));
		assertEquals(d4004, manager.data().getCeiling(0, b.addr(0x4003)));
		assertEquals(d4004, manager.definedUnits().getCeiling(0, b.addr(0x4003)));
		assertEquals(i4008, manager.instructions().getCeiling(0, b.addr(0x4003)));
		assertEquals(d4004, manager.definedData().getCeiling(0, b.addr(0x4003)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getCeiling(0, b.addr(0x4003)));

		assertEquals(d4004, manager.codeUnits().getCeiling(0, b.addr(0x4004)));
		assertEquals(d4004, manager.data().getCeiling(0, b.addr(0x4004)));
		assertEquals(d4004, manager.definedUnits().getCeiling(0, b.addr(0x4004)));
		assertEquals(i4008, manager.instructions().getCeiling(0, b.addr(0x4004)));
		assertEquals(d4004, manager.definedData().getCeiling(0, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getCeiling(0, b.addr(0x4004)));

		assertEquals(i4008, manager.codeUnits().getCeiling(0, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.data().getCeiling(0, b.addr(0x4005)));
		assertEquals(i4008, manager.definedUnits().getCeiling(0, b.addr(0x4005)));
		assertEquals(i4008, manager.instructions().getCeiling(0, b.addr(0x4005)));
		assertNull(manager.definedData().getCeiling(0, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getCeiling(0, b.addr(0x4005)));

		assertEquals(i4008, manager.codeUnits().getCeiling(0, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.data().getCeiling(0, b.addr(0x4006)));
		assertEquals(i4008, manager.definedUnits().getCeiling(0, b.addr(0x4006)));
		assertEquals(i4008, manager.instructions().getCeiling(0, b.addr(0x4006)));
		assertNull(manager.definedData().getCeiling(0, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getCeiling(0, b.addr(0x4006)));

		assertEquals(i4008, manager.codeUnits().getCeiling(0, b.addr(0x4007)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.data().getCeiling(0, b.addr(0x4007)));
		assertEquals(i4008, manager.definedUnits().getCeiling(0, b.addr(0x4007)));
		assertEquals(i4008, manager.instructions().getCeiling(0, b.addr(0x4007)));
		assertNull(manager.definedData().getCeiling(0, b.addr(0x4007)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getCeiling(0, b.addr(0x4007)));

		assertEquals(i4008, manager.codeUnits().getCeiling(0, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.data().getCeiling(0, b.addr(0x4008)));
		assertEquals(i4008, manager.definedUnits().getCeiling(0, b.addr(0x4008)));
		assertEquals(i4008, manager.instructions().getCeiling(0, b.addr(0x4008)));
		assertNull(manager.definedData().getCeiling(0, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getCeiling(0, b.addr(0x4008)));

		assertUndefinedWithAddr(b.addr(0x400a), manager.codeUnits().getCeiling(0, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.data().getCeiling(0, b.addr(0x4009)));
		assertNull(manager.definedUnits().getCeiling(0, b.addr(0x4009)));
		assertNull(manager.instructions().getCeiling(0, b.addr(0x4009)));
		assertNull(manager.definedData().getCeiling(0, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getCeiling(0, b.addr(0x4009)));

		// For the snap-6 tests, just check that the snap is heeded by view
		// Only check thoroughly the codeUnits view
		assertUndefinedWithAddr(b.addr(0x3fff), manager.codeUnits().getCeiling(0, b.addr(0x3fff)));
		assertEquals(d4000, manager.codeUnits().getCeiling(6, b.addr(0x4000)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getCeiling(6, b.addr(0x4001)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getCeiling(6, b.addr(0x4002)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getCeiling(6, b.addr(0x4003)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getCeiling(6, b.addr(0x4004)));

		assertUndefinedWithAddr(b.addr(0x4005), manager.codeUnits().getCeiling(6, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x4005), manager.data().getCeiling(6, b.addr(0x4005)));
		assertEquals(i4008, manager.definedUnits().getCeiling(6, b.addr(0x4005)));
		assertEquals(i4008, manager.instructions().getCeiling(6, b.addr(0x4005)));
		assertNull(manager.definedData().getCeiling(6, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x4005),
			manager.undefinedData().getCeiling(6, b.addr(0x4005)));

		assertUndefinedWithAddr(b.addr(0x4006), manager.codeUnits().getCeiling(6, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x4007), manager.codeUnits().getCeiling(6, b.addr(0x4007)));
		assertEquals(i4008, manager.codeUnits().getCeiling(6, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.codeUnits().getCeiling(6, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.codeUnits().getCeiling(6, b.addr(0x400a)));

		assertUndefinedWithAddr(b.addr(0x4000), manager.codeUnits().getCeiling(10, b.addr(0x4000)));
		assertUndefinedWithAddr(b.addr(0x4001), manager.codeUnits().getCeiling(10, b.addr(0x4001)));
		assertUndefinedWithAddr(b.addr(0x4002), manager.codeUnits().getCeiling(10, b.addr(0x4002)));
		assertUndefinedWithAddr(b.addr(0x4003), manager.codeUnits().getCeiling(10, b.addr(0x4003)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getCeiling(10, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x4005), manager.codeUnits().getCeiling(10, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x4006), manager.codeUnits().getCeiling(10, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x4007), manager.codeUnits().getCeiling(10, b.addr(0x4007)));
		assertUndefinedWithAddr(b.addr(0x4008), manager.codeUnits().getCeiling(10, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x4009), manager.codeUnits().getCeiling(10, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.codeUnits().getCeiling(10, b.addr(0x400a)));

		assertNull(manager.instructions().getCeiling(10, b.addr(0x3fff)));
	}

	@Test
	public void testGetAfter() throws CodeUnitInsertionException {
		TraceData d4000;
		TraceData d4004;
		TraceInstruction i4008;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			d4004 = b.addData(0, b.addr(0x4004), IntegerDataType.dataType, b.buf(5, 6, 7, 8));
			d4004.setEndSnap(5);
			i4008 = b.addInstruction(0, b.addr(0x4008), b.language, b.buf(0xf4, 0));
			i4008.setEndSnap(9);
		}

		assertEquals(d4000, manager.codeUnits().getAfter(0, b.addr(0x3fff)));
		assertEquals(d4000, manager.data().getAfter(0, b.addr(0x3fff)));
		assertEquals(d4000, manager.definedUnits().getAfter(0, b.addr(0x3fff)));
		assertEquals(i4008, manager.instructions().getAfter(0, b.addr(0x3fff)));
		assertEquals(d4000, manager.definedData().getAfter(0, b.addr(0x3fff)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getAfter(0, b.addr(0x3fff)));

		assertEquals(d4004, manager.codeUnits().getAfter(0, b.addr(0x4000)));
		assertEquals(d4004, manager.data().getAfter(0, b.addr(0x4000)));
		assertEquals(d4004, manager.definedUnits().getAfter(0, b.addr(0x4000)));
		assertEquals(i4008, manager.instructions().getAfter(0, b.addr(0x4000)));
		assertEquals(d4004, manager.definedData().getAfter(0, b.addr(0x4000)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getAfter(0, b.addr(0x4000)));

		assertEquals(d4004, manager.codeUnits().getAfter(0, b.addr(0x4001)));
		assertEquals(d4004, manager.data().getAfter(0, b.addr(0x4001)));
		assertEquals(d4004, manager.definedUnits().getAfter(0, b.addr(0x4001)));
		assertEquals(i4008, manager.instructions().getAfter(0, b.addr(0x4001)));
		assertEquals(d4004, manager.definedData().getAfter(0, b.addr(0x4001)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getAfter(0, b.addr(0x4001)));

		assertEquals(d4004, manager.codeUnits().getAfter(0, b.addr(0x4002)));
		assertEquals(d4004, manager.data().getAfter(0, b.addr(0x4002)));
		assertEquals(d4004, manager.definedUnits().getAfter(0, b.addr(0x4002)));
		assertEquals(i4008, manager.instructions().getAfter(0, b.addr(0x4002)));
		assertEquals(d4004, manager.definedData().getAfter(0, b.addr(0x4002)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getAfter(0, b.addr(0x4002)));

		assertEquals(d4004, manager.codeUnits().getAfter(0, b.addr(0x4003)));
		assertEquals(d4004, manager.data().getAfter(0, b.addr(0x4003)));
		assertEquals(d4004, manager.definedUnits().getAfter(0, b.addr(0x4003)));
		assertEquals(i4008, manager.instructions().getAfter(0, b.addr(0x4003)));
		assertEquals(d4004, manager.definedData().getAfter(0, b.addr(0x4003)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getAfter(0, b.addr(0x4003)));

		assertEquals(i4008, manager.codeUnits().getAfter(0, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.data().getAfter(0, b.addr(0x4004)));
		assertEquals(i4008, manager.definedUnits().getAfter(0, b.addr(0x4004)));
		assertEquals(i4008, manager.instructions().getAfter(0, b.addr(0x4004)));
		assertNull(manager.definedData().getAfter(0, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getAfter(0, b.addr(0x4004)));

		assertEquals(i4008, manager.codeUnits().getAfter(0, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.data().getAfter(0, b.addr(0x4005)));
		assertEquals(i4008, manager.definedUnits().getAfter(0, b.addr(0x4005)));
		assertEquals(i4008, manager.instructions().getAfter(0, b.addr(0x4005)));
		assertNull(manager.definedData().getAfter(0, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getAfter(0, b.addr(0x4005)));

		assertEquals(i4008, manager.codeUnits().getAfter(0, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.data().getAfter(0, b.addr(0x4006)));
		assertEquals(i4008, manager.definedUnits().getAfter(0, b.addr(0x4006)));
		assertEquals(i4008, manager.instructions().getAfter(0, b.addr(0x4006)));
		assertNull(manager.definedData().getAfter(0, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getAfter(0, b.addr(0x4006)));

		assertEquals(i4008, manager.codeUnits().getAfter(0, b.addr(0x4007)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.data().getAfter(0, b.addr(0x4007)));
		assertEquals(i4008, manager.definedUnits().getAfter(0, b.addr(0x4007)));
		assertEquals(i4008, manager.instructions().getAfter(0, b.addr(0x4007)));
		assertNull(manager.definedData().getAfter(0, b.addr(0x4007)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getAfter(0, b.addr(0x4007)));

		assertUndefinedWithAddr(b.addr(0x400a), manager.codeUnits().getAfter(0, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.data().getAfter(0, b.addr(0x4008)));
		assertNull(manager.definedUnits().getAfter(0, b.addr(0x4008)));
		assertNull(manager.instructions().getAfter(0, b.addr(0x4008)));
		assertNull(manager.definedData().getAfter(0, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getAfter(0, b.addr(0x4008)));

		assertUndefinedWithAddr(b.addr(0x400a), manager.codeUnits().getAfter(0, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.data().getAfter(0, b.addr(0x4009)));
		assertNull(manager.definedUnits().getAfter(0, b.addr(0x4009)));
		assertNull(manager.instructions().getAfter(0, b.addr(0x4009)));
		assertNull(manager.definedData().getAfter(0, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x400a),
			manager.undefinedData().getAfter(0, b.addr(0x4009)));

		// For the snap-6 tests, just check that the snap is heeded by view
		// Only check thoroughly the codeUnits view
		assertEquals(d4000, manager.codeUnits().getAfter(6, b.addr(0x3fff)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getAfter(6, b.addr(0x4000)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getAfter(6, b.addr(0x4001)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getAfter(6, b.addr(0x4002)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getAfter(6, b.addr(0x4003)));

		assertUndefinedWithAddr(b.addr(0x4005), manager.codeUnits().getAfter(6, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x4005), manager.data().getAfter(6, b.addr(0x4004)));
		assertEquals(i4008, manager.definedUnits().getAfter(6, b.addr(0x4004)));
		assertEquals(i4008, manager.instructions().getAfter(6, b.addr(0x4004)));
		assertNull(manager.definedData().getAfter(6, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x4005),
			manager.undefinedData().getAfter(6, b.addr(0x4004)));

		assertUndefinedWithAddr(b.addr(0x4006), manager.codeUnits().getAfter(6, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x4007), manager.codeUnits().getAfter(6, b.addr(0x4006)));
		assertEquals(i4008, manager.codeUnits().getAfter(6, b.addr(0x4007)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.codeUnits().getAfter(6, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.codeUnits().getAfter(6, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x400b), manager.codeUnits().getAfter(6, b.addr(0x400a)));

		assertUndefinedWithAddr(b.addr(0x4001), manager.codeUnits().getAfter(10, b.addr(0x4000)));
		assertUndefinedWithAddr(b.addr(0x4002), manager.codeUnits().getAfter(10, b.addr(0x4001)));
		assertUndefinedWithAddr(b.addr(0x4003), manager.codeUnits().getAfter(10, b.addr(0x4002)));
		assertUndefinedWithAddr(b.addr(0x4004), manager.codeUnits().getAfter(10, b.addr(0x4003)));
		assertUndefinedWithAddr(b.addr(0x4005), manager.codeUnits().getAfter(10, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x4006), manager.codeUnits().getAfter(10, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x4007), manager.codeUnits().getAfter(10, b.addr(0x4006)));
		assertUndefinedWithAddr(b.addr(0x4008), manager.codeUnits().getAfter(10, b.addr(0x4007)));
		assertUndefinedWithAddr(b.addr(0x4009), manager.codeUnits().getAfter(10, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x400a), manager.codeUnits().getAfter(10, b.addr(0x4009)));
		assertUndefinedWithAddr(b.addr(0x400b), manager.codeUnits().getAfter(10, b.addr(0x400a)));

		assertNull(manager.instructions().getAfter(10, b.addr(0x3fff)));

		// Nothing exists after MAX of data (second) space
		assertNull(manager.codeUnits().getAfter(0, b.data(-0x0001)));
	}

	protected <T> List<T> list(Iterable<T> it) {
		List<T> result = new ArrayList<>();
		for (T t : it) {
			result.add(t);
		}
		return result;
	}

	protected <T> List<T> listN(Iterable<T> it, int n) {
		List<T> result = new ArrayList<>(n);
		int i = 0;
		for (T t : it) {
			if (i >= n) {
				break;
			}
			result.add(t);
			i++;
		}
		return result;
	}

	protected void assertAllUndefined(final int count, Address start, long step,
			Iterable<? extends TraceCodeUnit> it) {
		int n = 0;
		Address cur = start;
		for (TraceCodeUnit cu : it) {
			assertUndefinedWithAddr(cur, cu);
			cur = cur.addWrap(step);
			n++;
			if (n > count) {
				break;
			}
		}
		assertEquals(count, n);
	}

	@Test
	public void testGet() throws CodeUnitInsertionException {
		assertAllUndefined(12, b.addr(0x3fff), 1,
			manager.codeUnits().get(0, b.addr(0x3fff), b.addr(0x400a), true));
		assertAllUndefined(12, b.addr(0x400a), -1,
			manager.codeUnits().get(0, b.addr(0x3fff), b.addr(0x400a), false));

		assertAllUndefined(12, b.addr(0x3fff), 1,
			manager.data().get(0, b.addr(0x3fff), b.addr(0x400a), true));
		assertAllUndefined(12, b.addr(0x400a), -1,
			manager.data().get(0, b.addr(0x3fff), b.addr(0x400a), false));

		assertEquals(List.of(),
			list(manager.definedUnits().get(0, b.addr(0x3fff), b.addr(0x400a), true)));
		assertEquals(List.of(),
			list(manager.definedUnits().get(0, b.addr(0x3fff), b.addr(0x400a), false)));

		assertEquals(List.of(),
			list(manager.instructions().get(0, b.addr(0x3fff), b.addr(0x400a), true)));
		assertEquals(List.of(),
			list(manager.instructions().get(0, b.addr(0x3fff), b.addr(0x400a), false)));

		assertEquals(List.of(),
			list(manager.definedData().get(0, b.addr(0x3fff), b.addr(0x400a), true)));
		assertEquals(List.of(),
			list(manager.definedData().get(0, b.addr(0x3fff), b.addr(0x400a), false)));

		assertAllUndefined(12, b.addr(0x3fff), 1,
			manager.undefinedData().get(0, b.addr(0x3fff), b.addr(0x400a), true));
		assertAllUndefined(12, b.addr(0x400a), -1,
			manager.undefinedData().get(0, b.addr(0x3fff), b.addr(0x400a), false));

		assertAllUndefined(4, b.addr(-0x0004), 1,
			manager.codeUnits().get(0, b.addr(-0x0004), b.addr(-0x0001), true));
		assertAllUndefined(4, b.addr(0x0003), -1,
			manager.codeUnits().get(0, b.addr(0x0000), b.addr(0x0003), false));

		TraceData d4000;
		TraceData d4004;
		TraceInstruction i4008;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			d4004 = b.addData(0, b.addr(0x4004), IntegerDataType.dataType, b.buf(5, 6, 7, 8));
			d4004.setEndSnap(5);
			i4008 = b.addInstruction(0, b.addr(0x4008), b.language, b.buf(0xf4, 0));
			i4008.setEndSnap(9);
		}
		TraceData u3fff = manager.undefinedData().getAt(0, b.addr(0x3fff));
		TraceData u400a = manager.undefinedData().getAt(0, b.addr(0x400a));

		assertEquals(List.of(u3fff, d4000, d4004, i4008, u400a),
			list(manager.codeUnits().get(0, b.addr(0x3fff), b.addr(0x400a), true)));
		assertEquals(List.of(u400a, i4008, d4004, d4000, u3fff),
			list(manager.codeUnits().get(0, b.addr(0x3fff), b.addr(0x400a), false)));

		assertEquals(List.of(u3fff, d4000, d4004, i4008, u400a),
			list(manager.codeUnits().get(0, b.range(0x3fff, 0x400a), true)));
		assertEquals(List.of(u400a, i4008, d4004, d4000, u3fff),
			list(manager.codeUnits().get(0, b.range(0x3fff, 0x400a), false)));

		assertEquals(List.of(d4000, i4008), list(manager.codeUnits()
				.get(0,
					b.set(b.range(0x4000, 0x4002), b.range(0x4008, 0x4008)), true)));
		assertEquals(List.of(i4008, d4000), list(manager.codeUnits()
				.get(0,
					b.set(b.range(0x4000, 0x4002), b.range(0x4008, 0x4008)), false)));

		assertEquals(List.of(u3fff, d4000, d4004, i4008, u400a),
			listN(manager.codeUnits().get(0, b.addr(0x3fff), true), 5));
		assertEquals(List.of(u400a, i4008, d4004, d4000, u3fff),
			listN(manager.codeUnits().get(0, b.addr(0x400a), false), 5));
	}

	@Test
	public void testAtSpaceBoundaries() throws CodeUnitInsertionException, IOException {
		assertUndefinedWithAddr(b.addr(-0x0001), manager.codeUnits().getBefore(0, b.data(0x0000)));
		assertUndefinedWithAddr(b.data(0x0000), manager.codeUnits().getAfter(0, b.addr(-0x0001)));

		assertUndefinedWithAddr(b.addr(-0x0001), manager.data().getBefore(0, b.data(0x0000)));
		assertUndefinedWithAddr(b.data(0x0000), manager.data().getAfter(0, b.addr(-0x0001)));

		assertNull(manager.definedUnits().getBefore(0, b.data(0x0000)));
		assertNull(manager.definedUnits().getAfter(0, b.addr(-0x0001)));

		assertNull(manager.instructions().getBefore(0, b.data(0x0000)));
		assertNull(manager.instructions().getAfter(0, b.addr(-0x0001)));

		assertNull(manager.definedData().getBefore(0, b.data(0x0000)));
		assertNull(manager.definedData().getAfter(0, b.addr(-0x0001)));

		assertUndefinedWithAddr(b.addr(-0x0001),
			manager.undefinedData().getBefore(0, b.data(0x0000)));
		assertUndefinedWithAddr(b.data(0x0000),
			manager.undefinedData().getAfter(0, b.addr(-0x0001)));

		TraceInstruction iCodeMax;
		try (UndoableTransaction tid = b.startTransaction()) {
			iCodeMax = b.addInstruction(0, b.addr(-0x0002), b.language, b.buf(0xf4, 0));
		}

		assertEquals(iCodeMax, manager.codeUnits().getBefore(0, b.data(0x0000)));
		assertEquals(iCodeMax, manager.definedUnits().getFloor(0, b.data(0x4000)));
		assertEquals(iCodeMax, manager.definedUnits().getBefore(0, b.data(0x0000)));
		assertEquals(iCodeMax, manager.instructions().getFloor(0, b.data(0x4000)));
		assertEquals(iCodeMax, manager.instructions().getBefore(0, b.data(0x0000)));
		assertNull(manager.definedData().getFloor(0, b.data(0x4000)));
		assertUndefinedWithAddr(b.addr(-0x0003),
			manager.undefinedData().getBefore(0, b.data(0x0000)));
		assertUndefinedWithAddr(b.data(0x0000),
			manager.undefinedData().getCeiling(0, b.addr(-0x0002)));

		b.trace.undo();

		TraceData dDataMin;
		try (UndoableTransaction tid = b.startTransaction()) {
			dDataMin = b.addData(0, b.data(0x0000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
		}

		assertEquals(dDataMin, manager.codeUnits().getAfter(0, b.addr(-0x0001)));
		assertEquals(dDataMin, manager.definedUnits().getCeiling(0, b.addr(0x4000)));
		assertEquals(dDataMin, manager.definedUnits().getAfter(0, b.addr(-0x0001)));
		assertNull(manager.instructions().getCeiling(0, b.addr(0x4000)));
		assertEquals(dDataMin, manager.definedData().getCeiling(0, b.addr(0x4000)));
		assertEquals(dDataMin, manager.definedData().getAfter(0, b.addr(-0x0001)));
		assertUndefinedWithAddr(b.data(0x0004),
			manager.undefinedData().getAfter(0, b.addr(-0x0001)));
		assertUndefinedWithAddr(b.addr(-0x0001),
			manager.undefinedData().getFloor(0, b.data(0x0003)));

		try (UndoableTransaction tid = b.startTransaction()) {
			iCodeMax = b.addInstruction(0, b.addr(-0x0002), b.language, b.buf(0xf4, 0));
		}
		TraceData uCodePre = manager.undefinedData().getAt(0, b.addr(-0x0003));
		assertUndefinedWithAddr(b.addr(-0x0003), uCodePre);
		TraceData uDataPost = manager.undefinedData().getAt(0, b.data(0x0004));
		assertUndefinedWithAddr(b.data(0x0004), uDataPost);

		assertEquals(List.of(uCodePre, iCodeMax, dDataMin, uDataPost),
			list(manager.codeUnits().get(0, b.addr(-0x0003), b.data(0x0004), true)));
		assertEquals(List.of(uDataPost, dDataMin, iCodeMax, uCodePre),
			list(manager.codeUnits().get(0, b.addr(-0x0003), b.data(0x0004), false)));

		// Also test single space at those boundaries (should get nothing)
		DBTraceCodeSpace dataSpace = manager.getForSpace(b.language.getDefaultDataSpace(), false);
		assertNotNull(dataSpace);
		assertNull(dataSpace.codeUnits().getBefore(0, b.data(0x0000)));
		assertNull(dataSpace.data().getBefore(0, b.data(0x0000)));
		assertNull(dataSpace.definedUnits().getBefore(0, b.data(0x0000)));
		assertNull(dataSpace.instructions().getBefore(0, b.data(0x0000)));
		assertNull(dataSpace.definedData().getBefore(0, b.data(0x0000)));
		assertNull(dataSpace.undefinedData().getBefore(0, b.data(0x0000)));

		DBTraceCodeSpace codeSpace = manager.getForSpace(b.language.getDefaultSpace(), false);
		assertNotNull(codeSpace);
		assertNull(codeSpace.codeUnits().getAfter(0, b.addr(-0x0001)));
		assertNull(codeSpace.data().getAfter(0, b.addr(-0x0001)));
		assertNull(codeSpace.definedUnits().getAfter(0, b.addr(-0x0001)));
		assertNull(codeSpace.instructions().getAfter(0, b.addr(-0x0001)));
		assertNull(codeSpace.definedData().getAfter(0, b.addr(-0x0001)));
		assertNull(codeSpace.undefinedData().getAfter(0, b.addr(-0x0001)));
	}

	@Test
	public void testGetsSingleSpace() throws CodeUnitInsertionException {
		TraceData d4000;
		TraceInstruction i4008;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			i4008 = b.addInstruction(0, b.addr(0x4008), b.language, b.buf(0xf4, 0));
			i4008.setEndSnap(9);
		}

		DBTraceCodeSpace codeSpace = manager.getForSpace(b.language.getDefaultSpace(), false);
		assertNotNull(codeSpace);

		assertEquals(d4000, codeSpace.codeUnits().getBefore(0, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x4004), codeSpace.codeUnits().getBefore(0, b.addr(0x4005)));
		assertEquals(d4000, codeSpace.codeUnits().getAfter(0, b.addr(0x3fff)));
		assertUndefinedWithAddr(b.addr(0x3fff), codeSpace.codeUnits().getAfter(0, b.addr(0x3ffe)));

		assertEquals(d4000, codeSpace.data().getBefore(0, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x4004), codeSpace.data().getBefore(0, b.addr(0x4005)));
		assertEquals(d4000, codeSpace.data().getAfter(0, b.addr(0x3fff)));
		assertUndefinedWithAddr(b.addr(0x3fff), codeSpace.data().getAfter(0, b.addr(0x3ffe)));

		assertEquals(d4000, codeSpace.definedUnits().getBefore(0, b.addr(0x4004)));
		assertEquals(d4000, codeSpace.definedUnits().getBefore(0, b.addr(0x4005)));
		assertEquals(d4000, codeSpace.definedUnits().getAfter(0, b.addr(0x3fff)));
		assertEquals(d4000, codeSpace.definedUnits().getAfter(0, b.addr(0x3ffe)));

		assertEquals(i4008, codeSpace.instructions().getBefore(0, b.addr(0x400a)));
		assertEquals(i4008, codeSpace.instructions().getBefore(0, b.addr(0x400b)));
		assertEquals(i4008, codeSpace.instructions().getAfter(0, b.addr(0x4007)));
		assertEquals(i4008, codeSpace.instructions().getAfter(0, b.addr(0x4006)));

		assertEquals(d4000, codeSpace.definedData().getBefore(0, b.addr(0x4004)));
		assertEquals(d4000, codeSpace.definedData().getBefore(0, b.addr(0x4005)));
		assertEquals(d4000, codeSpace.definedData().getAfter(0, b.addr(0x3fff)));
		assertEquals(d4000, codeSpace.definedData().getAfter(0, b.addr(0x3ffe)));

		assertUndefinedWithAddr(b.addr(0x3fff),
			codeSpace.undefinedData().getBefore(0, b.addr(0x4004)));
		assertUndefinedWithAddr(b.addr(0x4004),
			codeSpace.undefinedData().getBefore(0, b.addr(0x4005)));
		assertUndefinedWithAddr(b.addr(0x4004),
			codeSpace.undefinedData().getAfter(0, b.addr(0x3fff)));
		assertUndefinedWithAddr(b.addr(0x3fff),
			codeSpace.undefinedData().getAfter(0, b.addr(0x3ffe)));

		// Only one not covered via MemoryView is AddressSetView variant
		assertEquals(List.of(d4000, i4008),
			list(codeSpace.definedUnits().get(0, b.set(b.range(0x0000, -0x0001)), true)));
		assertEquals(List.of(i4008, d4000),
			list(codeSpace.definedUnits().get(0, b.set(b.range(0x0000, -0x0001)), false)));

		try { // Contains a range outside the selected space
			list(codeSpace.definedUnits()
					.get(0,
						b.set(b.range(0x4000, 0x5000), b.drng(0x4000, 0x5000)), true));
			fail();
		}
		catch (IllegalArgumentException e) {
			// pass
		}
	}

	@Test
	public void testRegisterSpace() throws Exception {
		DBTraceThread thread;
		DBTraceCodeRegisterSpace regCode;
		TraceData dR4;

		try (UndoableTransaction tid = b.startTransaction()) {
			thread = b.getOrAddThread("Thread 1", 0);
			regCode = manager.getCodeRegisterSpace(thread, true);
			dR4 = regCode.definedData()
					.create(Range.atLeast(0L), b.language.getRegister("r4"), LongDataType.dataType);
		}

		assertEquals(thread, regCode.codeUnits().getThread());
		assertEquals(thread, regCode.data().getThread());
		assertEquals(thread, regCode.definedUnits().getThread());
		assertEquals(thread, regCode.instructions().getThread());
		assertEquals(thread, regCode.definedData().getThread());
		assertEquals(thread, regCode.undefinedData().getThread());

		assertEquals(List.of(dR4), list(regCode.definedUnits().get(0, true)));

		DBTraceCodeRegisterSpace frameCode;
		TraceData dR5;

		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceStack stack = b.trace.getStackManager().getStack(thread, 0, true);
			stack.setDepth(2, true);
			assertEquals(regCode, manager.getCodeRegisterSpace(stack.getFrame(0, false), false));
			frameCode = manager.getCodeRegisterSpace(stack.getFrame(1, false), true);
			assertNotEquals(regCode, frameCode);
			dR5 = frameCode.definedData()
					.create(Range.atLeast(0L), b.language.getRegister("r5"), LongDataType.dataType);
		}

		assertEquals(1, frameCode.getFrameLevel());
		assertEquals(thread, frameCode.codeUnits().getThread());
		assertEquals(List.of(dR5), list(frameCode.definedUnits().get(0, true)));
	}

	@Test
	public void testGetAddressSetView() throws CodeUnitInsertionException {
		assertEquals(b.range(0x0000, -0x0001),
			manager.codeUnits().getAddressSetView(0).getRangeContaining(b.addr(0x4000)));
		assertEquals(b.range(0x0000, -0x0001),
			manager.data().getAddressSetView(0).getRangeContaining(b.addr(0x4000)));
		assertNull(manager.definedUnits().getAddressSetView(0).getRangeContaining(b.addr(0x4000)));
		assertNull(manager.instructions().getAddressSetView(0).getRangeContaining(b.addr(0x4000)));
		assertNull(manager.definedData().getAddressSetView(0).getRangeContaining(b.addr(0x4000)));
		assertEquals(b.range(0x0000, -0x0001),
			manager.undefinedData().getAddressSetView(0).getRangeContaining(b.addr(0x4000)));

		assertEquals(b.range(0x4000, 0x400b),
			manager.codeUnits()
					.getAddressSetView(0, b.range(0x4000, 0x400b))
					.getRangeContaining(
						b.addr(0x4000)));
		assertNull(
			manager.codeUnits()
					.getAddressSetView(0, b.range(0x4000, 0x400b))
					.getRangeContaining(
						b.addr(0x3fff)));

		assertNull(
			manager.definedUnits()
					.getAddressSetView(0, b.range(0x4000, 0x4005))
					.getRangeContaining(
						b.addr(0x4003)));

		TraceData d4000;
		TraceData d4004;
		TraceInstruction i4008;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			d4004 = b.addData(0, b.addr(0x4004), IntegerDataType.dataType, b.buf(5, 6, 7, 8));
			d4004.setEndSnap(5);
			i4008 = b.addInstruction(0, b.addr(0x4008), b.language, b.buf(0xf4, 0));
			i4008.setEndSnap(9);
		}

		assertEquals(b.range(0x0000, -0x0001),
			manager.codeUnits().getAddressSetView(0).getRangeContaining(b.addr(0x4000)));
		assertEquals(b.range(0x0000, 0x4007),
			manager.data().getAddressSetView(0).getRangeContaining(b.addr(0x4000)));
		assertNull(manager.data().getAddressSetView(0).getRangeContaining(b.addr(0x4008)));
		assertEquals(b.range(0x4000, 0x4009),
			manager.definedUnits().getAddressSetView(0).getRangeContaining(b.addr(0x4000)));
		assertNull(manager.definedUnits().getAddressSetView(0).getRangeContaining(b.addr(0x3fff)));
		assertEquals(b.range(0x4008, 0x4009),
			manager.instructions().getAddressSetView(0).getRangeContaining(b.addr(0x4008)));
		assertNull(manager.instructions().getAddressSetView(0).getRangeContaining(b.addr(0x4000)));
		assertEquals(b.range(0x4000, 0x4007),
			manager.definedData().getAddressSetView(0).getRangeContaining(b.addr(0x4000)));
		assertNull(manager.definedData().getAddressSetView(0).getRangeContaining(b.addr(0x4008)));
		assertEquals(b.range(0x0000, 0x3fff),
			manager.undefinedData().getAddressSetView(0).getRangeContaining(b.addr(0x3000)));
		assertNull(manager.undefinedData().getAddressSetView(0).getRangeContaining(b.addr(0x4000)));

		assertEquals(b.range(0x0000, -0x0001),
			manager.codeUnits().getAddressSetView(9).getRangeContaining(b.addr(0x4000)));
		assertEquals(b.range(0x0000, 0x4007),
			manager.data().getAddressSetView(9).getRangeContaining(b.addr(0x4000)));
		assertNull(manager.data().getAddressSetView(9).getRangeContaining(b.addr(0x4008)));
		assertEquals(b.range(0x4000, 0x4003),
			manager.definedUnits().getAddressSetView(9).getRangeContaining(b.addr(0x4000)));
		assertNull(manager.definedUnits().getAddressSetView(9).getRangeContaining(b.addr(0x4004)));
		assertEquals(b.range(0x4008, 0x4009),
			manager.instructions().getAddressSetView(9).getRangeContaining(b.addr(0x4008)));
		assertNull(manager.instructions().getAddressSetView(9).getRangeContaining(b.addr(0x4000)));
		assertEquals(b.range(0x4000, 0x4003),
			manager.definedData().getAddressSetView(9).getRangeContaining(b.addr(0x4000)));
		assertNull(manager.definedData().getAddressSetView(9).getRangeContaining(b.addr(0x4004)));
		assertEquals(b.range(0x0000, 0x3fff),
			manager.undefinedData().getAddressSetView(9).getRangeContaining(b.addr(0x3000)));
		assertNull(manager.undefinedData().getAddressSetView(9).getRangeContaining(b.addr(0x4000)));

		// See note in documentation regarding the -within- parameter
		assertEquals(b.range(0x4000, 0x4007),
			manager.definedUnits()
					.getAddressSetView(0, b.range(0x0000, 0x4005))
					.getRangeContaining(
						b.addr(0x4003)));
		// Check that the suggestion in the documentation yields the expected result
		assertEquals(b.range(0x4000, 0x4005),
			new IntersectionAddressSetView(
				manager.definedUnits().getAddressSetView(0, b.range(0x0000, 0x4005)),
				b.set(b.range(0x4000, 0x4005))).getRangeContaining(b.addr(0x4003)));
	}

	@Test
	public void testContainsAddress() throws CodeUnitInsertionException {
		assertTrue(manager.codeUnits().containsAddress(0, b.addr(0x4000)));
		assertTrue(manager.data().containsAddress(0, b.addr(0x4000)));
		assertFalse(manager.definedUnits().containsAddress(0, b.addr(0x4000)));
		assertFalse(manager.instructions().containsAddress(0, b.addr(0x4000)));
		assertFalse(manager.definedData().containsAddress(0, b.addr(0x4000)));
		assertTrue(manager.undefinedData().containsAddress(0, b.addr(0x4000)));

		TraceData d4000;
		TraceData d4004;
		TraceInstruction i4008;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			d4004 = b.addData(0, b.addr(0x4004), IntegerDataType.dataType, b.buf(5, 6, 7, 8));
			d4004.setEndSnap(5);
			i4008 = b.addInstruction(0, b.addr(0x4008), b.language, b.buf(0xf4, 0));
			i4008.setEndSnap(9);
		}

		assertTrue(manager.codeUnits().containsAddress(0, b.addr(0x4000)));
		assertTrue(manager.data().containsAddress(0, b.addr(0x4000)));
		assertFalse(manager.data().containsAddress(0, b.addr(0x4008)));
		assertTrue(manager.definedUnits().containsAddress(0, b.addr(0x4000)));
		assertFalse(manager.definedUnits().containsAddress(0, b.addr(0x3fff)));
		assertTrue(manager.instructions().containsAddress(0, b.addr(0x4008)));
		assertFalse(manager.instructions().containsAddress(0, b.addr(0x4000)));
		assertTrue(manager.definedData().containsAddress(0, b.addr(0x4000)));
		assertFalse(manager.definedData().containsAddress(0, b.addr(0x4008)));
		assertTrue(manager.undefinedData().containsAddress(0, b.addr(0x3fff)));
		assertFalse(manager.undefinedData().containsAddress(0, b.addr(0x4000)));

		assertTrue(manager.codeUnits().containsAddress(9, b.addr(0x4000)));
		assertTrue(manager.data().containsAddress(9, b.addr(0x4000)));
		assertFalse(manager.data().containsAddress(9, b.addr(0x4008)));
		assertTrue(manager.definedUnits().containsAddress(9, b.addr(0x4000)));
		assertFalse(manager.definedUnits().containsAddress(9, b.addr(0x4004)));
		assertTrue(manager.instructions().containsAddress(9, b.addr(0x4008)));
		assertFalse(manager.instructions().containsAddress(9, b.addr(0x4000)));
		assertTrue(manager.definedData().containsAddress(9, b.addr(0x4000)));
		assertFalse(manager.definedData().containsAddress(9, b.addr(0x4004)));
		assertTrue(manager.undefinedData().containsAddress(9, b.addr(0x4004)));
		assertFalse(manager.undefinedData().containsAddress(9, b.addr(0x4000)));
	}

	protected boolean coversTwoWays(TraceBaseCodeUnitsView<?> view, Range<Long> span,
			AddressRange range) {
		boolean first = view.coversRange(new ImmutableTraceAddressSnapRange(range, span));
		boolean second = view.coversRange(span, range);
		assertEquals(first, second);
		return first;
	}

	protected boolean intersectsTwoWays(TraceBaseCodeUnitsView<?> view, Range<Long> span,
			AddressRange range) {
		boolean first = view.intersectsRange(new ImmutableTraceAddressSnapRange(range, span));
		boolean second = view.intersectsRange(span, range);
		assertEquals(first, second);
		return first;
	}

	@Test
	public void testCoversIntersectsRange() throws CodeUnitInsertionException {
		AddressRange all = b.range(0, -1);

		assertTrue(coversTwoWays(manager.codeUnits(), Range.all(), all));
		assertTrue(intersectsTwoWays(manager.codeUnits(), Range.all(), all));

		assertTrue(coversTwoWays(manager.data(), Range.all(), all));
		assertTrue(intersectsTwoWays(manager.data(), Range.all(), all));

		assertFalse(coversTwoWays(manager.definedUnits(), Range.all(), all));
		assertFalse(intersectsTwoWays(manager.definedUnits(), Range.all(), all));

		assertFalse(coversTwoWays(manager.instructions(), Range.all(), all));
		assertFalse(intersectsTwoWays(manager.instructions(), Range.all(), all));

		assertFalse(coversTwoWays(manager.definedData(), Range.all(), all));
		assertFalse(intersectsTwoWays(manager.definedData(), Range.all(), all));

		assertTrue(coversTwoWays(manager.undefinedData(), Range.all(), all));
		assertTrue(intersectsTwoWays(manager.undefinedData(), Range.all(), all));

		TraceData d4000;
		TraceData d4004;
		TraceInstruction i4008;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			d4004 = b.addData(0, b.addr(0x4004), IntegerDataType.dataType, b.buf(5, 6, 7, 8));
			d4004.setEndSnap(5);
			i4008 = b.addInstruction(0, b.addr(0x4008), b.language, b.buf(0xf4, 0));
			i4008.setEndSnap(9);
		}

		assertTrue(coversTwoWays(manager.codeUnits(), Range.all(), all));
		assertTrue(intersectsTwoWays(manager.codeUnits(), Range.all(), all));

		assertFalse(coversTwoWays(manager.data(), Range.all(), all));
		assertTrue(intersectsTwoWays(manager.data(), Range.all(), all));
		assertTrue(coversTwoWays(manager.data(), Range.all(), b.range(0x0000, 0x4007)));
		assertTrue(coversTwoWays(manager.data(), Range.all(), b.range(0x400a, -0x0001)));
		assertTrue(coversTwoWays(manager.data(), Range.atMost(-1L), all));
		assertTrue(coversTwoWays(manager.data(), Range.atLeast(10L), all));
		assertFalse(
			intersectsTwoWays(manager.data(), Range.closed(0L, 9L), b.range(0x4008, 0x4009)));

		assertFalse(coversTwoWays(manager.definedUnits(), Range.all(), all));
		assertTrue(intersectsTwoWays(manager.definedUnits(), Range.all(), all));
		assertTrue(
			coversTwoWays(manager.definedUnits(), Range.closed(0L, 5L), b.range(0x4000, 0x4009)));
		assertTrue(
			coversTwoWays(manager.definedUnits(), Range.closed(0L, 9L), b.range(0x4001, 0x4003)));
		assertTrue(
			coversTwoWays(manager.definedUnits(), Range.closed(0L, 9L), b.range(0x4008, 0x4009)));
		assertFalse(
			intersectsTwoWays(manager.definedUnits(), Range.all(), b.range(0x0000, 0x3fff)));
		assertFalse(
			intersectsTwoWays(manager.definedUnits(), Range.all(), b.range(0x400a, -0x0001)));
		assertFalse(intersectsTwoWays(manager.definedUnits(), Range.atMost(-1L), all));
		assertFalse(intersectsTwoWays(manager.definedUnits(), Range.atLeast(10L), all));
		assertFalse(
			intersectsTwoWays(manager.definedUnits(), Range.atLeast(6L), b.range(0x4004, 0x4007)));

		assertFalse(coversTwoWays(manager.instructions(), Range.all(), all));
		assertTrue(intersectsTwoWays(manager.instructions(), Range.all(), all));
		assertTrue(
			coversTwoWays(manager.instructions(), Range.closed(0L, 9L), b.range(0x4008, 0x4009)));
		assertFalse(intersectsTwoWays(manager.instructions(), Range.atMost(-1L), all));
		assertFalse(intersectsTwoWays(manager.instructions(), Range.atLeast(10L), all));
		assertFalse(
			intersectsTwoWays(manager.instructions(), Range.all(), b.range(0x0000, 0x4007)));
		assertFalse(
			intersectsTwoWays(manager.instructions(), Range.all(), b.range(0x400a, -0x0001)));

		assertFalse(coversTwoWays(manager.definedData(), Range.all(), all));
		assertTrue(intersectsTwoWays(manager.definedData(), Range.all(), all));
		assertTrue(
			coversTwoWays(manager.definedData(), Range.closed(0L, 5L), b.range(0x4000, 0x4007)));
		assertTrue(
			coversTwoWays(manager.definedData(), Range.closed(0L, 9L), b.range(0x4001, 0x4003)));
		assertFalse(intersectsTwoWays(manager.definedData(), Range.all(), b.range(0x0000, 0x3fff)));
		assertFalse(
			intersectsTwoWays(manager.definedData(), Range.all(), b.range(0x4008, -0x0001)));
		assertFalse(intersectsTwoWays(manager.definedData(), Range.atMost(-1L), all));
		assertFalse(intersectsTwoWays(manager.definedData(), Range.atLeast(10L), all));
		assertFalse(
			intersectsTwoWays(manager.definedData(), Range.atLeast(6L), b.range(0x4004, -0x0001)));

		assertFalse(coversTwoWays(manager.undefinedData(), Range.all(), all));
		assertTrue(intersectsTwoWays(manager.undefinedData(), Range.all(), all));
		assertTrue(coversTwoWays(manager.undefinedData(), Range.all(), b.range(0x0000, 0x3fff)));
		assertTrue(coversTwoWays(manager.undefinedData(), Range.all(), b.range(0x400a, -0x0001)));
		assertTrue(coversTwoWays(manager.undefinedData(), Range.atMost(-1L), all));
		assertTrue(coversTwoWays(manager.undefinedData(), Range.atLeast(10L), all));
		assertTrue(
			coversTwoWays(manager.undefinedData(), Range.atLeast(6L), b.range(0x4004, 0x4007)));
		assertFalse(intersectsTwoWays(manager.undefinedData(), Range.closed(0L, 5L),
			b.range(0x4000, 0x4009)));
		assertFalse(intersectsTwoWays(manager.undefinedData(), Range.closed(0L, 9L),
			b.range(0x4001, 0x4003)));
		assertFalse(intersectsTwoWays(manager.undefinedData(), Range.closed(0L, 9L),
			b.range(0x4008, 0x4009)));
	}

	@Test
	public void testClear() throws CodeUnitInsertionException, CancelledException, IOException {
		TraceData d4000;
		TraceData d4004;
		TraceInstruction i4008;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			d4004 = b.addData(0, b.addr(0x4004), IntegerDataType.dataType, b.buf(5, 6, 7, 8));
			d4004.setEndSnap(5);
			i4008 = b.addInstruction(0, b.addr(0x4008), b.language, b.buf(0xf4, 0));
			i4008.setEndSnap(9);
		}

		assertEquals(d4000, manager.definedUnits().getAt(0, b.addr(0x4000)));
		try (UndoableTransaction tid = b.startTransaction()) {
			manager.definedUnits()
					.clear(Range.all(), b.range(0x0000, -0x0001), false,
						TaskMonitor.DUMMY);
		}
		assertNull(manager.definedUnits().getAt(0, b.addr(0x4000)));
		assertNull(manager.definedUnits().getAt(0, b.addr(0x4004)));
		assertNull(manager.definedUnits().getAt(0, b.addr(0x4008)));
		assertUndefinedWithAddr(b.addr(0x4000), manager.codeUnits().getAt(0, b.addr(0x4000)));

		b.trace.undo();
		d4000 = manager.definedData().getAt(0, b.addr(0x4000));
		d4004 = manager.definedData().getAt(0, b.addr(0x4004));
		i4008 = manager.instructions().getAt(0, b.addr(0x4008));

		assertEquals(d4000, manager.definedUnits().getAt(7, b.addr(0x4000)));
		try (UndoableTransaction tid = b.startTransaction()) {
			manager.definedUnits()
					.clear(Range.closed(7L, 8L), b.range(0x0000, -0x0001), false,
						TaskMonitor.DUMMY);
		}
		assertNull(manager.definedUnits().getAt(7, b.addr(0x4000)));
		assertNull(manager.definedUnits().getAt(7, b.addr(0x4004)));
		assertNull(manager.definedUnits().getAt(7, b.addr(0x4008)));
		assertEquals(Range.closed(0L, 6L), d4000.getLifespan());
		assertEquals(Range.closed(0L, 5L), d4004.getLifespan());
		assertEquals(Range.closed(0L, 6L), i4008.getLifespan());

		b.trace.undo();
		d4000 = manager.definedData().getAt(0, b.addr(0x4000));
		d4004 = manager.definedData().getAt(0, b.addr(0x4004));
		i4008 = manager.instructions().getAt(0, b.addr(0x4008));

		assertEquals(d4000, manager.definedUnits().getAt(7, b.addr(0x4000)));
		try (UndoableTransaction tid = b.startTransaction()) {
			manager.definedUnits()
					.clear(Range.closed(7L, 8L), b.range(0x4000, 0x4000), false,
						TaskMonitor.DUMMY);
		}
		assertNull(manager.definedUnits().getAt(7, b.addr(0x4000)));
		assertEquals(d4004, manager.definedUnits().getAt(5, b.addr(0x4004)));
		assertEquals(i4008, manager.definedUnits().getAt(7, b.addr(0x4008)));
		assertEquals(Range.closed(0L, 6L), d4000.getLifespan());
		assertEquals(Range.closed(0L, 5L), d4004.getLifespan());
		assertEquals(Range.closed(0L, 9L), i4008.getLifespan());

		b.trace.undo();
		d4000 = manager.definedData().getAt(0, b.addr(0x4000));
		d4004 = manager.definedData().getAt(0, b.addr(0x4004));
		i4008 = manager.instructions().getAt(0, b.addr(0x4008));

		assertEquals(d4000, manager.definedUnits().getAt(0, b.addr(0x4000)));
		try (UndoableTransaction tid = b.startTransaction()) {
			manager.instructions()
					.clear(Range.all(), b.range(0x0000, -0x0001), false,
						TaskMonitor.DUMMY);
		}
		assertEquals(d4000, manager.definedUnits().getAt(0, b.addr(0x4000)));
		assertEquals(d4004, manager.definedUnits().getAt(0, b.addr(0x4004)));
		assertNull(manager.definedUnits().getAt(0, b.addr(0x4008)));

		b.trace.undo();
		d4000 = manager.definedData().getAt(0, b.addr(0x4000));
		d4004 = manager.definedData().getAt(0, b.addr(0x4004));
		i4008 = manager.instructions().getAt(0, b.addr(0x4008));

		assertEquals(d4000, manager.definedUnits().getAt(0, b.addr(0x4000)));
		try (UndoableTransaction tid = b.startTransaction()) {
			manager.definedData()
					.clear(Range.all(), b.range(0x0000, -0x0001), false,
						TaskMonitor.DUMMY);
		}
		assertNull(manager.definedUnits().getAt(0, b.addr(0x4000)));
		assertNull(manager.definedUnits().getAt(0, b.addr(0x4004)));
		assertEquals(i4008, manager.definedUnits().getAt(0, b.addr(0x4008)));

		// TODO: Verify events fire
	}

	@Test
	public void testClearWithClearContext() throws CodeUnitInsertionException,
			ContextChangeException, CancelledException, IOException {
		DBTraceRegisterContextManager ctxManager = b.trace.getRegisterContextManager();
		Register r4 = b.language.getRegister("r4");
		RegisterValue rvOne = new RegisterValue(r4, BigInteger.ONE);

		TraceData d4000;
		TraceData d4004;
		TraceInstruction i4008;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), IntegerDataType.dataType, b.buf(1, 2, 3, 4));
			d4000.setEndSnap(9);
			d4004 = b.addData(0, b.addr(0x4004), IntegerDataType.dataType, b.buf(5, 6, 7, 8));
			d4004.setEndSnap(5);
			i4008 = b.addInstruction(0, b.addr(0x4008), b.language, b.buf(0xf4, 0));
			i4008.setEndSnap(9);

			// Clear one of the data before a context space is created
			manager.definedUnits()
					.clear(Range.all(), b.range(0x4004, 0x4004), true,
						TaskMonitor.DUMMY);

			i4008.setRegisterValue(rvOne);
		}
		assertEquals(rvOne, ctxManager.getValue(b.language, r4, 0, b.addr(0x4008)));
		assertEquals(rvOne, ctxManager.getValue(b.language, r4, 7, b.addr(0x4008)));

		try (UndoableTransaction tid = b.startTransaction()) {
			manager.instructions()
					.clear(Range.all(), b.range(0x0000, -0x0001), true,
						TaskMonitor.DUMMY);
		}
		assertNull(ctxManager.getValue(b.language, r4, 0, b.addr(0x4008)));

		b.trace.undo();
		assertEquals(rvOne, ctxManager.getValue(b.language, r4, 0, b.addr(0x4008)));
		assertEquals(rvOne, ctxManager.getValue(b.language, r4, 7, b.addr(0x4008)));

		try (UndoableTransaction tid = b.startTransaction()) {
			manager.instructions()
					.clear(Range.closed(7L, 7L), b.range(0x0000, -0x0001), true,
						TaskMonitor.DUMMY);
		}
		assertNull(ctxManager.getValue(b.language, r4, 7, b.addr(0x4008)));
		assertEquals(rvOne, ctxManager.getValue(b.language, r4, 6, b.addr(0x4008)));
	}

	@Test
	@Ignore("Looks related to GP-479")
	public void testAddGuestInstructionThenRemoveAndDelete() throws AddressOverflowException,
			CodeUnitInsertionException, IOException, CancelledException {
		DBTraceLanguageManager langMan = b.trace.getLanguageManager();
		Language x86 = getSLEIGH_X86_LANGUAGE();
		DBTraceGuestLanguage guest;
		DBTraceGuestLanguageMappedRange mappedRange;

		TraceInstruction g4000;
		TraceInstruction i4001;
		TraceData d4003;
		try (UndoableTransaction tid = b.startTransaction()) {
			guest = langMan.addGuestLanguage(x86);
			mappedRange = guest.addMappedRange(b.addr(0x0000), b.addr(guest, 0x0000), 1L << 32);
			g4000 = b.addInstruction(0, b.addr(0x4000), x86, b.buf(0x90));
			i4001 = b.addInstruction(0, b.addr(0x4001), b.language, b.buf(0xf4, 0));
			d4003 = b.addData(0, b.addr(0x4003), LongDataType.dataType, b.buf(1, 2, 3, 4));
		}

		assertEquals(g4000, manager.codeUnits().getAt(0, b.addr(0x4000)));
		try (UndoableTransaction tid = b.startTransaction()) {
			mappedRange.delete(new ConsoleTaskMonitor());
		}
		assertUndefinedWithAddr(b.addr(0x4000), manager.codeUnits().getAt(0, b.addr(0x4000)));
		assertEquals(i4001, manager.codeUnits().getAt(0, b.addr(0x4001)));
		assertEquals(d4003, manager.codeUnits().getAt(0, b.addr(0x4003)));

		b.trace.undo();

		assertEquals(g4000, manager.codeUnits().getAt(0, b.addr(0x4000)));
		try (UndoableTransaction tid = b.startTransaction()) {
			guest.delete(new ConsoleTaskMonitor());
		}
		assertUndefinedWithAddr(b.addr(0x4000), manager.codeUnits().getAt(0, b.addr(0x4000)));
		assertEquals(i4001, manager.codeUnits().getAt(0, b.addr(0x4001)));
		assertEquals(d4003, manager.codeUnits().getAt(0, b.addr(0x4003)));
	}

	@Test
	public void testSaveAndLoad() throws Exception {
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));

			DBTraceThread thread = b.getOrAddThread("Thread 1", 0);
			DBTraceCodeRegisterSpace regCode = manager.getCodeRegisterSpace(thread, true);
			regCode.definedData()
					.create(Range.atLeast(0L), b.language.getRegister("r4"),
						LongDataType.dataType);
		}

		File file = b.save();
		try (@SuppressWarnings("hiding")
		ToyDBTraceBuilder b = new ToyDBTraceBuilder(file)) {
			@SuppressWarnings("hiding")
			DBTraceCodeManager manager = b.trace.getCodeManager();

			// No transaction, so it had better exist
			DBTraceThread thread = b.getOrAddThread("Thread 1", 0);
			List<TraceCodeUnit> units = new ArrayList<>();
			for (TraceCodeUnit u : manager.definedUnits().get(0, true)) {
				units.add(u);
			}
			// Again, no transaction, so that space had better exist
			for (TraceCodeUnit u : manager.getCodeRegisterSpace(thread, true)
					.definedUnits()
					.get(0,
						true)) {
				units.add(u);
			}

			assertEquals(2, units.size());

			assertTrue(units.get(0) instanceof TraceInstruction);
			TraceInstruction instruction = (TraceInstruction) units.get(0);
			assertEquals(b.addr(0x4004), instruction.getAddress());
			assertEquals("ret", instruction.getMnemonicString()); // Meh
			assertEquals(2, instruction.getLength());

			assertTrue(units.get(1) instanceof TraceData);
			TraceData data = (TraceData) units.get(1);
			assertEquals(b.language.getRegister("r4").getAddress(), data.getAddress());
			assertEquals(new Scalar(32, 0), data.getValue());
			assertEquals(4, data.getLength());
		}
	}

	@Test
	public void testUndoThenRedo() throws Exception {
		try (UndoableTransaction tid = b.startTransaction()) {
			b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));

			DBTraceThread thread = b.getOrAddThread("Thread 1", 0);
			DBTraceCodeRegisterSpace regCode = manager.getCodeRegisterSpace(thread, true);
			regCode.definedData()
					.create(Range.atLeast(0L), b.language.getRegister("r4"),
						LongDataType.dataType);
		}

		b.trace.undo();

		assertFalse(manager.definedUnits().get(0, true).iterator().hasNext());
		assertTrue(b.trace.getThreadManager().getAllThreads().isEmpty());

		b.trace.redo();

		// No transaction, so it had better exist
		DBTraceThread thread = b.getOrAddThread("Thread 1", 0);
		List<TraceCodeUnit> units = new ArrayList<>();
		for (TraceCodeUnit u : manager.definedUnits().get(0, true)) {
			units.add(u);
		}
		// Again, no transaction, so that space had better exist
		for (TraceCodeUnit u : manager.getCodeRegisterSpace(thread, true)
				.definedUnits()
				.get(0,
					true)) {
			units.add(u);
		}

		assertEquals(2, units.size());

		assertTrue(units.get(0) instanceof TraceInstruction);
		TraceInstruction instruction = (TraceInstruction) units.get(0);
		assertEquals(b.addr(0x4004), instruction.getAddress());
		assertEquals("ret", instruction.getMnemonicString()); // Meh
		assertEquals(2, instruction.getLength());

		assertTrue(units.get(1) instanceof TraceData);
		TraceData data = (TraceData) units.get(1);
		assertEquals(b.language.getRegister("r4").getAddress(), data.getAddress());
		assertEquals(new Scalar(32, 0), data.getValue());
		assertEquals(4, data.getLength());
	}

	// TODO: Test using a context-sensitive language
	// TODO: Test using delay-slotted instructions (DBTraceCodemanager#instructionMax)
	// TODO: How are lifespans of delay-slotted instructions bound to thatof the jump?
	// TODO: In language manager, test deleting a language clears instructions
	// TODO: In language manager, test unmapping a language clears instructions
}
