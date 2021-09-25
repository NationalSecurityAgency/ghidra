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

import java.io.IOException;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.*;

import com.google.common.collect.Range;

import db.IntField;
import db.StringField;
import ghidra.app.plugin.assembler.*;
import ghidra.docking.settings.Settings;
import ghidra.lifecycle.Unfinished;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.model.util.TypeMismatchException;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.listing.DBTraceCommentAdapter.DBTraceCommentEntry;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.memory.DBTraceMemoryRegisterSpace;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.database.symbol.DBTraceReference;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.language.TraceGuestLanguage;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.listing.TraceInstruction;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceOverlappedRegionException;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.model.symbol.TraceStackReference;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.*;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NoValueException;
import ghidra.util.prop.PropertyVisitor;

public class DBTraceCodeUnitTest extends AbstractGhidraHeadlessIntegrationTest
		implements Unfinished {
	protected static final String[] EMPTY_STRING_ARRAY = new String[] {};

	protected static class TestSaveable implements Saveable {
		protected static Class<?>[] FIELDS = new Class<?>[] { IntField.class, StringField.class };
		private int f1;
		private String f2;

		public TestSaveable() {
		}

		@Override
		public String toString() {
			return "TestSaveable(" + f1 + "," + f2 + ")";
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof TestSaveable)) {
				return false;
			}
			TestSaveable that = (TestSaveable) obj;
			if (this.f1 != that.f1) {
				return false;
			}
			if (!Objects.equals(this.f2, that.f2)) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			return Objects.hash(f1, f2);
		}

		public TestSaveable(int f1, String f2) {
			this.f1 = f1;
			this.f2 = f2;
		}

		@Override
		public Class<?>[] getObjectStorageFields() {
			return FIELDS;
		}

		@Override
		public void save(ObjectStorage objStorage) {
			objStorage.putInt(f1);
			objStorage.putString(f2);
		}

		@Override
		public void restore(ObjectStorage objStorage) {
			f1 = objStorage.getInt();
			f2 = objStorage.getString();
		}

		@Override
		public int getSchemaVersion() {
			return 0;
		}

		@Override
		public boolean isUpgradeable(int oldSchemaVersion) {
			return false;
		}

		@Override
		public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion,
				ObjectStorage currentObjStorage) {
			return false;
		}

		@Override
		public boolean isPrivate() {
			return false;
		}
	}

	protected static class TestPropertyVisitor implements PropertyVisitor {
		Class<?> type = null;
		Object val = null;

		Pair<Class<?>, Object> getAndReset() {
			Pair<Class<?>, Object> ret = new ImmutablePair<>(type, val);
			type = null;
			val = null;
			return ret;
		}

		boolean isSet() {
			return type != null;
		}

		@Override
		public void visit() {
			assertNull(type);
			type = Void.class;
		}

		@Override
		public void visit(String value) {
			assertNull(type);
			type = String.class;
			val = value;
		}

		@Override
		public void visit(Object value) {
			assertNull(type);
			type = Object.class;
			val = value;
		}

		@Override
		public void visit(Saveable value) {
			assertNull(type);
			type = Saveable.class;
			val = value;
		}

		@Override
		public void visit(int value) {
			assertNull(type);
			type = Integer.class;
			val = value;
		}
	}

	protected static <T> Set<T> set(Iterator<T> it) {
		Set<T> result = new HashSet<>();
		while (it.hasNext()) {
			result.add(it.next());
		}
		return result;
	}

	protected static <T> Set<T> set(Iterable<T> it) {
		Set<T> result = new HashSet<>();
		for (T t : it) {
			result.add(t);
		}
		return result;
	}

	protected static <T> List<T> list(Iterable<T> it) {
		List<T> result = new ArrayList<>();
		for (T t : it) {
			result.add(t);
		}
		return result;
	}

	protected <T> Set<T> set(T[] arr) {
		return new HashSet<>(Arrays.asList(arr));
	}

	ToyDBTraceBuilder b;
	DBTraceCodeManager manager;

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
	public void testCodeUnitLocationGetters() throws CodeUnitInsertionException,
			TraceOverlappedRegionException, DuplicateNameException {
		TraceInstruction ins;
		try (UndoableTransaction tid = b.startTransaction()) {
			ins = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
		}
		TraceData und = manager.undefinedData().getAt(0, b.addr(0x4006));

		assertEquals(b.addr(0x4004), ins.getAddress());
		assertEquals(b.addr(0x4006), und.getAddress());

		assertEquals(b.addr(0x4004), ins.getMinAddress());
		assertEquals(b.addr(0x4005), ins.getMaxAddress());
		assertEquals(b.addr(0x4006), und.getMinAddress());
		assertEquals(b.addr(0x4006), und.getMaxAddress());

		assertEquals(0, ins.getStartSnap());
		assertEquals(Range.atLeast(0L), ins.getLifespan());
		assertEquals(0, und.getStartSnap());
		assertEquals(Range.closed(0L, 0L), und.getLifespan());

		// NOTE: Seems wrong. If so, problem is in Address, not TraceCodeUnit
		assertEquals("00004004", ins.getAddressString(false, false));
		assertEquals("0000000000004004", ins.getAddressString(false, true));
		assertEquals("ram:00004004", ins.getAddressString(true, false));
		assertEquals("ram:0000000000004004", ins.getAddressString(true, true));

		try (UndoableTransaction tid = b.startTransaction()) {
			b.trace.getMemoryManager()
					.addRegion(".text", Range.atLeast(0L),
						b.range(0x4000, 0x4fff), TraceMemoryFlag.READ);
		}

		assertEquals("00004004", ins.getAddressString(false, false));
		assertEquals("0000000000004004", ins.getAddressString(false, true));
		assertEquals(".text:00004004", ins.getAddressString(true, false));
		assertEquals(".text:0000000000004004", ins.getAddressString(true, true));
	}

	@Test
	public void testGetProgram() throws CodeUnitInsertionException {
		TraceInstruction i4004;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
		}

		assertEquals(0, i4004.getProgram().getSnap());
	}

	@Test
	public void testGetMemory() throws CodeUnitInsertionException {
		TraceInstruction i4004;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
		}

		assertEquals(i4004.getProgram().getMemory(), i4004.getMemory());
	}

	@Test
	public void testIsBigEndian() throws CodeUnitInsertionException, AddressOverflowException {
		Language x86 = getSLEIGH_X86_LANGUAGE();
		TraceGuestLanguage guest;
		TraceInstruction i4004;
		TraceInstruction g4006;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
			guest = b.trace.getLanguageManager().addGuestLanguage(x86);
			guest.addMappedRange(b.addr(0x0000), b.addr(guest, 0x0000), 1L << 32);
			g4006 = b.addInstruction(0, b.addr(0x4006), x86, b.buf(0x90));
		}

		assertTrue(i4004.isBigEndian());
		assertFalse(g4006.isBigEndian());
	}

	@Test
	public void testPropertySettersGetters() throws CodeUnitInsertionException, NoValueException {
		TraceInstruction i4004;
		TraceInstruction i4006;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
			i4006 = b.addInstruction(0, b.addr(0x4006), b.language, b.buf(0xf4, 0));
		}
		assertFalse(i4004.hasProperty("myVoid"));

		assertFalse(i4004.getVoidProperty("myVoid"));
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setProperty("myVoid");
		}
		assertTrue(i4004.hasProperty("myVoid"));
		assertFalse(i4006.hasProperty("myVoid"));
		assertNull(i4004.getProperty("myVoid", Void.class));
		assertNull(i4006.getProperty("myVoid", Void.class));
		assertNull(i4004.getProperty("myVoid", Object.class));
		assertTrue(i4004.getVoidProperty("myVoid"));
		assertFalse(i4006.getVoidProperty("myVoid"));
		try {
			i4006.getIntProperty("myVoid");
			fail();
		}
		catch (TypeMismatchException e) {
			// pass
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setProperty("myInt", 0x1234);
		}
		assertTrue(i4004.hasProperty("myInt"));
		assertFalse(i4006.hasProperty("myInt"));
		assertEquals(0x1234, i4004.getProperty("myInt", Integer.class).intValue());
		assertNull(i4006.getProperty("myInt", Integer.class));
		assertEquals(Integer.valueOf(0x1234), i4004.getProperty("myInt", Object.class));
		assertEquals(0x1234, i4004.getIntProperty("myInt"));
		try {
			i4006.getIntProperty("myInt");
		}
		catch (NoValueException e) {
			// pass
		}
		try {
			i4006.getVoidProperty("myInt");
			fail();
		}
		catch (TypeMismatchException e) {
			// pass
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setProperty("myString", "Hello!");
		}
		assertTrue(i4004.hasProperty("myString"));
		assertFalse(i4006.hasProperty("myString"));
		assertEquals("Hello!", i4004.getProperty("myString", String.class));
		assertNull(i4006.getProperty("myString", String.class));
		assertEquals("Hello!", i4004.getProperty("myString", Object.class));
		assertEquals("Hello!", i4004.getStringProperty("myString"));
		assertNull(i4006.getStringProperty("myString"));
		try {
			i4006.getIntProperty("myString");
			fail();
		}
		catch (TypeMismatchException e) {
			// pass
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setProperty("mySaveable", TestSaveable.class,
				new TestSaveable(0x5678, "Good bye!"));
			i4004.setProperty("myObject", new TestSaveable(0x9abc, "Bonjour!"));
			i4004.setTypedProperty("myT", new TestSaveable(0xdef0, "Au revoir!"));
		}

		assertTrue(i4004.hasProperty("mySaveable"));
		assertFalse(i4006.hasProperty("mySaveable"));
		// Use a local variable to verify return type
		TestSaveable testSaveable = i4004.getProperty("mySaveable", TestSaveable.class);
		assertEquals(new TestSaveable(0x5678, "Good bye!"), testSaveable);
		assertNull(i4006.getProperty("mySaveable", TestSaveable.class));
		assertEquals(new TestSaveable(0x9abc, "Bonjour!"),
			i4004.getProperty("myObject", TestSaveable.class));
		assertEquals(new TestSaveable(0xdef0, "Au revoir!"),
			i4004.getProperty("myT", TestSaveable.class));
		assertEquals(new TestSaveable(0x5678, "Good bye!"), i4004.getObjectProperty("mySaveable"));
		assertEquals(new TestSaveable(0x9abc, "Bonjour!"), i4004.getObjectProperty("myObject"));
		assertEquals(new TestSaveable(0xdef0, "Au revoir!"), i4004.getObjectProperty("myT"));
		assertNull(i4006.getObjectProperty("mySaveable"));

		assertEquals(Set.of("myVoid", "myInt", "myString", "mySaveable", "myObject", "myT"),
			set(i4004.propertyNames()));
		assertEquals(Set.of(), set(i4006.propertyNames()));

		TestPropertyVisitor visitor = new TestPropertyVisitor();

		i4004.visitProperty(visitor, "noProperty");
		assertFalse(visitor.isSet());
		i4004.visitProperty(visitor, "myVoid");
		assertEquals(new ImmutablePair<>(Void.class, null), visitor.getAndReset());
		i4006.visitProperty(visitor, "myVoid");
		assertFalse(visitor.isSet());
		i4004.visitProperty(visitor, "myInt");
		assertEquals(new ImmutablePair<>(Integer.class, 0x1234), visitor.getAndReset());
		i4006.visitProperty(visitor, "myInt");
		assertFalse(visitor.isSet());
		i4004.visitProperty(visitor, "myString");
		assertEquals(new ImmutablePair<>(String.class, "Hello!"), visitor.getAndReset());
		i4004.visitProperty(visitor, "mySaveable");
		assertEquals(new ImmutablePair<>(Saveable.class, new TestSaveable(0x5678, "Good bye!")),
			visitor.getAndReset());

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.removeProperty("myVoid");
			i4006.removeProperty("myVoid"); // NOP
			i4004.removeProperty("noProperty");
		}
		assertFalse(i4004.hasProperty("myVoid"));
		assertEquals(Set.of("myInt", "myString", "mySaveable", "myObject", "myT"),
			set(i4004.propertyNames()));
	}

	@Test
	public void testDetectNewCommentTypes()
			throws IllegalArgumentException, IllegalAccessException {
		for (Field f : CodeUnit.class.getFields()) {
			if (f.getName().endsWith("_COMMENT")) {
				if (f.getInt(null) > CodeUnit.REPEATABLE_COMMENT) {
					fail("It appears a new comment type was added");
				}
			}
		}
	}

	@Test
	public void testCommentSettersGetters() throws CodeUnitInsertionException {
		TraceInstruction i4004;
		TraceInstruction i4006;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
			i4006 = b.addInstruction(0, b.addr(0x4006), b.language, b.buf(0xf4, 0));
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setComment(CodeUnit.NO_COMMENT, "Shouldn't work");
			fail();
		}
		catch (IllegalArgumentException e) {
			// pass
		}
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setComment(5, "Shouldn't work");
			fail();
		}
		catch (IllegalArgumentException e) {
			// pass
		}

		assertNull(i4004.getComment(CodeUnit.EOL_COMMENT));
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setComment(CodeUnit.EOL_COMMENT, "My EOL Comment");
		}
		assertEquals("My EOL Comment", i4004.getComment(CodeUnit.EOL_COMMENT));
		assertNull(i4006.getComment(CodeUnit.EOL_COMMENT));

		assertArrayEquals(EMPTY_STRING_ARRAY, i4004.getCommentAsArray(CodeUnit.PRE_COMMENT));
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setCommentAsArray(CodeUnit.PRE_COMMENT, new String[] { "My", "Pre", "Comment" });
		}
		assertEquals("My EOL Comment", i4004.getComment(CodeUnit.EOL_COMMENT));
		assertArrayEquals(new String[] { "My", "Pre", "Comment" },
			i4004.getCommentAsArray(CodeUnit.PRE_COMMENT));
		assertArrayEquals(EMPTY_STRING_ARRAY, i4006.getCommentAsArray(CodeUnit.PRE_COMMENT));
		assertEquals("My\nPre\nComment", i4004.getComment(CodeUnit.PRE_COMMENT));

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setCommentAsArray(CodeUnit.PRE_COMMENT, null);
			i4006.setCommentAsArray(CodeUnit.PRE_COMMENT, null); // NOP
		}
		assertNull(i4004.getComment(CodeUnit.PRE_COMMENT));

		TraceInstruction i4004_10;
		DBTraceCommentAdapter commentAdapter = b.trace.getCommentAdapter();

		DBTraceCommentEntry c4004 =
			commentAdapter.reduce(TraceAddressSnapRangeQuery.at(b.addr(0x4004), 0)).firstValue();
		assertNotNull(c4004);

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setEndSnap(9);
			i4006.setEndSnap(9);
			// TODO: Decide whether or not to shrink the comment lifespan with the unit lifespan 
			assertEquals(Range.atLeast(0L), c4004.getLifespan());

			i4004_10 = b.addInstruction(10, b.addr(0x4004), b.language);
			i4004_10.setComment(CodeUnit.PRE_COMMENT, "Get this back in the mix");
			i4004_10.setComment(CodeUnit.EOL_COMMENT, "A different comment");
		}
		assertEquals(Range.closed(0L, 9L), c4004.getLifespan());
		assertEquals("My EOL Comment", i4004.getComment(CodeUnit.EOL_COMMENT));

		try (UndoableTransaction tid = b.startTransaction()) {
			commentAdapter.clearComments(Range.atLeast(0L), b.range(0x4000, 0x5000),
				CodeUnit.EOL_COMMENT);
		}
		assertNull(i4004.getComment(CodeUnit.EOL_COMMENT));
		assertEquals("Get this back in the mix", i4004_10.getComment(CodeUnit.PRE_COMMENT));

		try (UndoableTransaction tid = b.startTransaction()) {
			commentAdapter.clearComments(Range.atLeast(0L), b.range(0x4000, 0x5000),
				CodeUnit.NO_COMMENT);
		}
		assertNull(i4004.getComment(CodeUnit.EOL_COMMENT));
		assertNull(i4004_10.getComment(CodeUnit.PRE_COMMENT));
	}

	@Test
	public void testAddressRelators() throws CodeUnitInsertionException {
		TraceInstruction i4004;
		TraceInstruction i4006;
		TraceData d4008;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
			i4006 = b.addInstruction(0, b.addr(0x4006), b.language, b.buf(0xf4, 0));
			d4008 = b.addData(0, b.addr(0x4008), LongDataType.dataType, b.buf(1, 2, 3, 4));
		}

		assertTrue(i4004.isSuccessor(i4006));
		assertFalse(i4004.isSuccessor(d4008));

		assertFalse(i4004.contains(b.addr(0x4003)));
		assertTrue(i4004.contains(b.addr(0x4004)));
		assertTrue(i4004.contains(b.addr(0x4005)));
		assertFalse(i4004.contains(b.addr(0x4006)));

		assertEquals(-1, i4004.compareTo(b.addr(0x4003)));
		assertEquals(0, i4004.compareTo(b.addr(0x4004)));
		assertEquals(0, i4004.compareTo(b.addr(0x4005)));
		assertEquals(1, i4004.compareTo(b.addr(0x4006)));
	}

	@Test
	public void testReferenceSettersGetters() throws CodeUnitInsertionException {
		TraceData d4000;
		TraceInstruction i4004;
		TraceInstruction i4006;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), LongDataType.dataType, b.buf(1, 2, 3, 4));
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
			i4006 = b.addInstruction(0, b.addr(0x4006), b.language, b.buf(0xf4, 0));
		}
		Set<TraceReference> refs;

		assertArrayEquals(new TraceReference[] {}, d4000.getValueReferences());
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000.addValueReference(b.addr(0x5000), RefType.DATA); // ODD: No source parameter?
		}
		refs = set(d4000.getValueReferences());
		assertEquals(1, refs.size());
		TraceReference valueRef = refs.iterator().next();
		assertEquals(Range.atLeast(0L), valueRef.getLifespan());
		assertEquals(b.addr(0x4000), valueRef.getFromAddress());
		assertEquals(b.addr(0x5000), valueRef.getToAddress());
		assertEquals(RefType.DATA, valueRef.getReferenceType());
		assertEquals(SourceType.USER_DEFINED, valueRef.getSource());
		assertEquals(0, valueRef.getOperandIndex());

		assertArrayEquals(new TraceReference[] {}, i4004.getMnemonicReferences());
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.addMnemonicReference(b.addr(0x5000), RefType.READ, SourceType.USER_DEFINED);
		}
		refs = set(i4004.getMnemonicReferences());
		assertEquals(1, refs.size());
		TraceReference mnemRef = refs.iterator().next();
		assertEquals(Range.atLeast(0L), mnemRef.getLifespan());
		assertEquals(b.addr(0x4004), mnemRef.getFromAddress());
		assertEquals(b.addr(0x5000), mnemRef.getToAddress());
		assertEquals(RefType.READ, mnemRef.getReferenceType());
		assertEquals(SourceType.USER_DEFINED, mnemRef.getSource());
		assertEquals(CodeUnit.MNEMONIC, mnemRef.getOperandIndex());
		assertEquals(0, i4006.getMnemonicReferences().length);

		// TODO: Should I be allowed to add an operand reference for a non-existent operand?
		assertArrayEquals(new TraceReference[] {}, i4004.getOperandReferences(0));
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.addOperandReference(0, b.addr(0x5001), RefType.WRITE, SourceType.USER_DEFINED);
		}
		refs = set(i4004.getOperandReferences(0));
		assertEquals(1, refs.size());
		assertEquals(0, i4004.getOperandReferences(1).length);
		TraceReference opRef = refs.iterator().next();
		assertEquals(Range.atLeast(0L), opRef.getLifespan());
		assertEquals(b.addr(0x4004), opRef.getFromAddress());
		assertEquals(b.addr(0x5001), opRef.getToAddress());
		assertEquals(RefType.WRITE, opRef.getReferenceType());
		assertEquals(SourceType.USER_DEFINED, opRef.getSource());
		assertEquals(0, opRef.getOperandIndex());

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setStackReference(CodeUnit.MNEMONIC, -0x30, SourceType.USER_DEFINED,
				RefType.READ);
		}
		refs = set(i4004.getMnemonicReferences());
		assertEquals(2, refs.size());
		assertTrue(refs.remove(mnemRef));
		TraceStackReference stackRef = (TraceStackReference) refs.iterator().next();
		assertTrue(stackRef.isStackReference());
		assertEquals(Range.atLeast(0L), stackRef.getLifespan());
		assertEquals(b.addr(0x4004), stackRef.getFromAddress());
		assertEquals(-0x30, stackRef.getStackOffset());
		assertEquals(RefType.READ, stackRef.getReferenceType());
		assertEquals(SourceType.USER_DEFINED, stackRef.getSource());
		assertEquals(CodeUnit.MNEMONIC, stackRef.getOperandIndex());

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setRegisterReference(CodeUnit.MNEMONIC, b.language.getRegister("r4"),
				SourceType.USER_DEFINED, RefType.READ);
		}
		refs = set(i4004.getMnemonicReferences());
		assertEquals(3, refs.size());
		assertTrue(refs.remove(mnemRef));
		assertTrue(refs.remove(stackRef));
		TraceReference regRef = refs.iterator().next();
		assertTrue(regRef.isRegisterReference());
		assertEquals(Range.atLeast(0L), regRef.getLifespan());
		assertEquals(b.addr(0x4004), regRef.getFromAddress());
		assertEquals(b.language.getRegister("r4").getAddress(), regRef.getToAddress());
		assertEquals(RefType.READ, regRef.getReferenceType());
		assertEquals(SourceType.USER_DEFINED, regRef.getSource());
		assertEquals(CodeUnit.MNEMONIC, regRef.getOperandIndex());

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setPrimaryMemoryReference(stackRef);
		}
		assertEquals(stackRef, i4004.getPrimaryReference(CodeUnit.MNEMONIC));

		assertEquals(Set.of(mnemRef, opRef, stackRef, regRef), set(i4004.getReferencesFrom()));

		DBTraceReference refTo;
		try (UndoableTransaction tid = b.startTransaction()) {
			refTo = b.trace.getReferenceManager()
					.addMemoryReference(Range.all(), b.addr(0x3000),
						b.addr(0x4004), RefType.COMPUTED_JUMP, SourceType.USER_DEFINED,
						CodeUnit.MNEMONIC);
		}
		assertEquals(Set.of(refTo), set((Iterator<Reference>) i4004.getReferenceIteratorTo()));

		assertNull(i4004.getExternalReference(CodeUnit.MNEMONIC));

		try (UndoableTransaction tid = b.startTransaction()) {
			d4000.removeValueReference(b.addr(0x6000)); // NOP
		}
		assertEquals(Set.of(valueRef), set(d4000.getValueReferences()));

		try (UndoableTransaction tid = b.startTransaction()) {
			d4000.removeValueReference(b.addr(0x5000));
		}
		assertArrayEquals(new TraceReference[] {}, d4000.getValueReferences());

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.removeMnemonicReference(b.addr(0x6000)); // NOP
		}
		assertEquals(Set.of(mnemRef, stackRef, regRef), set(i4004.getMnemonicReferences()));

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.removeMnemonicReference(b.addr(0x5000));
		}
		assertEquals(Set.of(stackRef, regRef), set(i4004.getMnemonicReferences()));

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.removeOperandReference(0, b.addr(0x5001)); // NOP
		}
		assertEquals(0, i4004.getOperandReferences(1).length);

		try (UndoableTransaction tid = b.startTransaction()) {
			// All modules should be loaded in trace.
			i4004.removeExternalReference(CodeUnit.MNEMONIC);
			fail();
		}
		catch (UnsupportedOperationException e) {
			// pass
		}
	}

	@Test
	public void testCodeUnitOwnerGetters() throws Exception {
		TraceThread thread;
		TraceInstruction instruction;
		TraceData data;
		TraceData undefined;
		TraceData undReg;
		try (UndoableTransaction tid = b.startTransaction()) {
			instruction = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
			undefined = manager.undefinedData().getAt(0, b.addr(0x4006));

			thread = b.getOrAddThread("Thread 1", 0);
			DBTraceCodeRegisterSpace regCode = manager.getCodeRegisterSpace(thread, true);
			data = regCode.definedData()
					.create(Range.atLeast(0L), b.language.getRegister("r4"),
						LongDataType.dataType);
			// getForRegister requires unit to match size
			undReg = regCode.undefinedData().getAt(0, b.language.getRegister("r5").getAddress());
		}

		assertEquals(b.trace, instruction.getTrace());
		assertNull(instruction.getThread());

		assertEquals(b.trace, data.getTrace());
		assertEquals(thread, data.getThread());

		assertEquals(b.trace, undefined.getTrace());
		assertNull(undefined.getThread());

		assertEquals(b.trace, undReg.getTrace());
		assertEquals(thread, undReg.getThread());
	}

	@Test
	public void testSetEndSnap() throws CodeUnitInsertionException {
		TraceData d4000;
		TraceInstruction i4004;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), LongDataType.dataType, b.buf(1, 2, 3, 4));
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));

			d4000.setEndSnap(9);
			assertEquals(Range.closed(0L, 9L), d4000.getLifespan());

			i4004.setEndSnap(9);
			assertEquals(Range.closed(0L, 9L), i4004.getLifespan());

			d4000.setEndSnap(0);
			assertEquals(Range.closed(0L, 0L), d4000.getLifespan());

			i4004.setEndSnap(0);
			assertEquals(Range.closed(0L, 0L), i4004.getLifespan());

			try {
				i4004.setEndSnap(-1);
				fail();
			}
			catch (IllegalArgumentException e) {
				// pass;
			}

			try {
				d4000.setEndSnap(-1);
				fail();
			}
			catch (IllegalArgumentException e) {
				// pass;
			}

			// TODO: Test listen for events
		}
		TraceData u4006 = manager.undefinedData().getAt(0, b.addr(0x4007));
		try (UndoableTransaction tid = b.startTransaction()) {
			u4006.setEndSnap(10);
			fail();
		}
		catch (UnsupportedOperationException e) {
			// pass
		}
	}

	@Test
	public void testGetBytes() throws Exception {
		Language x86 = getSLEIGH_X86_LANGUAGE();
		TraceGuestLanguage guest;

		TraceData data;
		TraceData und;
		TraceData reg;
		TraceInstruction lil;
		try (UndoableTransaction tid = b.startTransaction()) {
			data = b.addData(0, b.addr(0x4000), LongDataType.dataType, b.buf(1, 2, 3, 4));
			// In space without memory, yet.
			und = manager.undefinedData().getAt(0, b.data(0x7fff));

			DBTraceThread thread = b.getOrAddThread("Thread1", 0);
			DBTraceMemoryRegisterSpace regMem =
				b.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			Register r4 = b.language.getRegister("r4");
			regMem.putBytes(0, r4, b.buf(1, 2, 3, 4, 5, 6, 7, 8));
			DBTraceCodeRegisterSpace regCode = manager.getCodeRegisterSpace(thread, true);
			reg = regCode.definedData().create(Range.atLeast(0L), r4, PointerDataType.dataType);

			guest = b.trace.getLanguageManager().addGuestLanguage(x86);
			guest.addMappedRange(b.addr(0x0000), b.addr(guest, 0x0000), 1L << 32);
			lil = b.addInstruction(0, b.addr(0x4008), x86, b.buf(0xeb, 0xfe));
		}
		ByteBuffer buf;

		buf = ByteBuffer.allocate(4);
		assertEquals(4, data.getBytes(buf, 0));
		assertArrayEquals(b.arr(1, 2, 3, 4), buf.array());

		try (UndoableTransaction tid = b.startTransaction()) {
			data = b.addData(0, b.addr(0x4004), LongDataType.dataType, b.buf(1, 2, 3, 4));
		}
		buf = ByteBuffer.allocate(1);
		assertEquals(1, data.getBytes(buf, 0));
		assertArrayEquals(b.arr(1), buf.array());

		buf = ByteBuffer.allocate(10);
		buf.position(5);
		buf.limit(7);
		assertEquals(2, data.getBytes(buf, 1));
		assertArrayEquals(b.arr(0, 0, 0, 0, 0, 2, 3, 0, 0, 0), buf.array());

		buf = ByteBuffer.allocate(5);
		assertEquals(5, data.getBytes(buf, 3));
		assertArrayEquals(b.arr(4, 0xeb, 0xfe, 0, 0), buf.array());

		buf = ByteBuffer.allocate(4);
		assertEquals(4, data.getBytes(buf, 0));
		assertArrayEquals(b.arr(1, 2, 3, 4), buf.array());

		assertArrayEquals(b.arr(1, 2, 3, 4), data.getBytes());

		byte[] arr = new byte[6];
		data.getBytesInCodeUnit(arr, 1);
		assertArrayEquals(b.arr(0, 1, 2, 3, 4, 0), arr);

		buf = ByteBuffer.allocate(1);
		assertEquals(0, und.getBytes(buf, 0)); // Because the memory space has not been created
		try (UndoableTransaction tid = b.startTransaction()) {
			DBTraceMemorySpace dataMem =
				b.trace.getMemoryManager().getMemorySpace(b.language.getDefaultDataSpace(), true);
			dataMem.putBytes(0, b.data(0x7fff), b.buf(5, 6, 7, 8));
		}
		assertEquals(1, und.getBytes(buf, 0));
		assertArrayEquals(b.arr(5), buf.array());

		assertArrayEquals(b.arr(1, 2, 3, 4, 5, 6, 7, 8), reg.getBytes());

		assertArrayEquals(b.arr(0xeb, 0xfe), lil.getBytes());

		assertEquals(0x1, data.getByte(0));
		assertEquals(0x102, data.getShort(0));
		assertEquals(0x1020304, data.getInt(0));
		assertEquals(0x1020304ebfe0000L, data.getLong(0));
		assertEquals(new BigInteger("1020304", 16), data.getBigInteger(0, 4, false));
		assertEquals(new BigInteger("1020304", 16), data.getBigInteger(0, 4, true));

		assertEquals(-0x15, lil.getByte(0));
		assertEquals(-0x115, lil.getShort(0));
		assertEquals(0xfeeb, lil.getInt(0));
		assertEquals(0xfeeb, lil.getLong(0));
		assertEquals(new BigInteger("feeb", 16), lil.getBigInteger(0, 2, false));
		assertEquals(new BigInteger("-115", 16), lil.getBigInteger(0, 2, true));
	}

	@Test
	@Ignore
	public void testFigureOutAssembly() throws AssemblySyntaxException, AssemblySemanticException {
		Assembler asm = Assemblers.getAssembler(b.language);
		System.out.println(
			NumericUtilities.convertBytesToString(asm.assembleLine(b.addr(0x4024), "call 0x4004")));
	}

	@Test
	public void testDataValueGetters() throws TraceOverlappedRegionException,
			DuplicateNameException, CodeUnitInsertionException {
		Union myUnion = new UnionDataType("myUnion");
		myUnion.add(ShortDataType.dataType);

		Structure myStruct = new StructureDataType("myStruct", 0);
		myStruct.add(LongDataType.dataType);

		Array myArray = new ArrayDataType(ByteDataType.dataType, 4, 1);

		TraceData dl4000;
		TraceData dp4006;
		TraceData ds400e;
		TraceData du4012;
		TraceData ds4014;
		TraceData da4018;
		TraceData dd401c;
		try (UndoableTransaction tid = b.startTransaction()) {
			// StringDataType accesses memory via program view, so "block" must exist
			b.trace.getMemoryManager()
					.addRegion("myRegion", Range.atLeast(0L),
						b.range(0x4000, 0x4fff), TraceMemoryFlag.READ);

			dl4000 = b.addData(0, b.addr(0x4000), LongDataType.dataType, b.buf(1, 2, 3, 4));
			dp4006 = b.addData(0, b.addr(0x4006), PointerDataType.dataType,
				b.buf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00));
			ds400e = b.addData(0, b.addr(0x400e), StringDataType.dataType, b.buf('s', 't', 'r', 0));
			du4012 = b.addData(0, b.addr(0x4012), myUnion, b.buf(1, 2));
			ds4014 = b.addData(0, b.addr(0x4014), myStruct, b.buf(5, 6, 7, 8));
			da4018 = b.addData(0, b.addr(0x4018), myArray, b.buf(9, 10, 11, 12));
			dd401c = b.addData(0, b.addr(0x401c), new RepeatedStringDataType(),
				b.buf(0, 1, 's', 't', 'r', '0', '1', 0));
		}
		TraceData u3fff = manager.undefinedData().getAt(0, b.addr(0x3fff));

		assertNull(u3fff.getAddress(0));
		assertNull(dl4000.getAddress(0));
		assertEquals(b.addr(0x4000), dp4006.getAddress(0));
		assertNull(dp4006.getAddress(-1));
		assertNull(ds400e.getAddress(0));
		assertNull(du4012.getAddress(0));
		assertNull(ds4014.getAddress(0));
		assertNull(da4018.getAddress(0));
		assertNull(dd401c.getAddress(0));

		assertEquals(new Scalar(8, 0), u3fff.getScalar(0));
		assertNull(u3fff.getScalar(-1));
		assertEquals(new Scalar(32, 0x1020304), dl4000.getScalar(0));
		assertNull(dl4000.getScalar(-1));
		assertEquals(new Scalar(64, 0x4000), dp4006.getScalar(0));
		assertNull(dp4006.getScalar(-1));
		assertNull(ds400e.getScalar(0));
		assertNull(du4012.getScalar(0));
		assertNull(ds4014.getScalar(0));
		assertNull(da4018.getScalar(0));
		assertNull(dd401c.getScalar(0));

		assertEquals(new Scalar(8, 0), u3fff.getValue());
		assertEquals(new Scalar(32, 0x1020304), dl4000.getValue());
		assertEquals(b.addr(0x4000), dp4006.getValue());
		assertEquals("str", ds400e.getValue());
		assertNull(du4012.getValue()); // NOTE: A bit unexpected, but OK.
		assertNull(ds4014.getValue());
		assertNull(da4018.getValue());
		assertNull(dd401c.getValue());

		assertNull(u3fff.getValueClass());
		assertEquals(Scalar.class, dl4000.getValueClass());
		assertEquals(Address.class, dp4006.getValueClass());
		assertEquals(String.class, ds400e.getValueClass());
		assertNull(du4012.getValueClass());
		assertNull(ds4014.getValueClass());
		// TODO: I wonder if they meant java.lang.reflect.Array???
		// Hard to tell, since value came back null....
		assertEquals(Array.class, da4018.getValueClass());
		assertNull(dd401c.getValueClass());

		assertFalse(u3fff.hasStringValue());
		assertFalse(dl4000.hasStringValue());
		assertFalse(dp4006.hasStringValue());
		assertTrue(ds400e.hasStringValue());
		assertFalse(du4012.hasStringValue());
		assertFalse(ds4014.hasStringValue());
		assertFalse(da4018.hasStringValue());
		assertFalse(dd401c.hasStringValue());

		assertFalse(u3fff.isPointer());
		assertFalse(dl4000.isPointer());
		assertTrue(dp4006.isPointer());
		assertFalse(ds400e.isPointer());
		assertFalse(du4012.isPointer());
		assertFalse(ds4014.isPointer());
		assertFalse(da4018.isPointer());
		assertFalse(dd401c.isPointer());

		assertFalse(u3fff.isUnion());
		assertFalse(dl4000.isUnion());
		assertFalse(dp4006.isUnion());
		assertFalse(ds400e.isUnion());
		assertTrue(du4012.isUnion());
		assertFalse(ds4014.isUnion());
		assertFalse(da4018.isUnion());
		assertFalse(dd401c.isUnion());

		assertFalse(u3fff.isStructure());
		assertFalse(dl4000.isStructure());
		assertFalse(dp4006.isStructure());
		assertFalse(ds400e.isStructure());
		assertFalse(du4012.isStructure());
		assertTrue(ds4014.isStructure());
		assertFalse(da4018.isStructure());
		assertFalse(dd401c.isStructure());

		assertFalse(u3fff.isArray());
		assertFalse(dl4000.isArray());
		assertFalse(dp4006.isArray());
		assertFalse(ds400e.isArray());
		assertFalse(du4012.isArray());
		assertFalse(ds4014.isArray());
		assertTrue(da4018.isArray());
		assertFalse(dd401c.isArray());

		assertFalse(u3fff.isDynamic());
		assertFalse(dl4000.isDynamic());
		assertFalse(dp4006.isDynamic());
		assertFalse(ds400e.isDynamic());
		assertFalse(du4012.isDynamic());
		assertFalse(ds4014.isDynamic());
		assertFalse(da4018.isDynamic());
		assertTrue(dd401c.isDynamic());

		assertEquals("00h", u3fff.getDefaultValueRepresentation());
		assertEquals("1020304h", dl4000.getDefaultValueRepresentation());
		assertEquals("ram:00004000", dp4006.getDefaultValueRepresentation());
		assertEquals("\"str\"", ds400e.getDefaultValueRepresentation());
		assertEquals("", du4012.getDefaultValueRepresentation());
		assertEquals("", ds4014.getDefaultValueRepresentation());
		assertEquals("", da4018.getDefaultValueRepresentation());
		assertEquals("", dd401c.getDefaultValueRepresentation());
	}

	@Test
	public void testInstructionOperandAndFlowSettersGetters() throws CodeUnitInsertionException,
			TraceOverlappedRegionException, DuplicateNameException {
		Register r4 = b.language.getRegister("r4");
		Register lr = b.language.getRegister("lr");
		Register fC = b.language.getRegister("C");
		Register fZ = b.language.getRegister("Z");
		Register fN = b.language.getRegister("N");
		Register fV = b.language.getRegister("V");

		TraceInstruction i4004;
		TraceInstruction i4006;
		TraceInstruction i4008;
		TraceInstruction i400a;
		try (UndoableTransaction tid = b.startTransaction()) {
			// Disassembler's new cacheing in mem-buffer uses program view, so "block" must exist
			b.trace.getMemoryManager()
					.addRegion("myRegion", Range.atLeast(0L),
						b.range(0x4000, 0x4fff), TraceMemoryFlag.READ);

			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xc8, 0x47));
			assertEquals("add r4,#0x7", i4004.toString());
			i4006 = b.addInstruction(0, b.addr(0x4006), b.language, b.buf(0xf4, 0));
			assertEquals("ret", i4006.toString());
			i4008 = b.addInstruction(0, b.addr(0x4008), b.language, b.buf(0xff, 0xfc));
			assertEquals("call 0x00004004", i4008.toString());
			i400a = b.addInstruction(0, b.addr(0x400a), b.language, b.buf(0xf6, 0x40));
			assertEquals("call r4", i400a.toString());
		}

		assertNull(i4004.getAddress(-1));
		assertNull(i4004.getAddress(0));
		assertNull(i4004.getAddress(1));
		assertEquals(b.addr(0x4004), i4008.getAddress(0));

		assertNull(i4004.getScalar(0));
		assertEquals(new Scalar(16, 7), i4004.getScalar(1));
		assertNull(i4008.getScalar(0)); // Unlike Data, Instruction does not convert

		assertEquals(r4, i4004.getRegister(0));
		assertNull(i4004.getRegister(1));
		assertNull(i4008.getRegister(0));

		assertArrayEquals(new Object[] { r4 }, i4004.getOpObjects(0));
		assertArrayEquals(new Object[] { new Scalar(16, 7) }, i4004.getOpObjects(1));
		assertArrayEquals(new Object[] { b.addr(0x4004) }, i4008.getOpObjects(0));

		// TODO: Where does this 64-bit 0 come from?
		assertEquals(Set.of(r4, new Scalar(64, 0), new Scalar(16, 7)),
			set(i4004.getInputObjects()));
		// TODO: What is this 64-bit 0x400a? fall-through offset?
		// Where did the -0x4 (0xfc) go?
		assertEquals(Set.of(new Scalar(64, 0x400a)), set(i4008.getInputObjects()));
		// Sanity check re/ comments above
		assertEquals("0x00004004", i4008.getDefaultOperandRepresentation(0));

		assertEquals(Set.of(r4, fC, fZ, fN, fV), set(i4004.getResultObjects()));
		assertEquals(Set.of(lr), set(i4008.getResultObjects()));

		// Seems DYNAMIC is the default/error result
		assertEquals(OperandType.DYNAMIC, i4004.getOperandType(-1));
		assertEquals(OperandType.REGISTER, i4004.getOperandType(0));
		// Not IMMEDIATE?
		assertEquals(OperandType.SCALAR, i4004.getOperandType(1));
		assertEquals(OperandType.DYNAMIC, i4004.getOperandType(2));
		// Not RELATIVE?
		assertEquals(OperandType.ADDRESS | OperandType.CODE, i4008.getOperandType(0));

		assertNull(i4004.getOperandRefType(-1));
		assertEquals(RefType.READ_WRITE, i4004.getOperandRefType(0));
		assertEquals(RefType.DATA, i4004.getOperandRefType(1));
		assertNull(i4004.getOperandRefType(2));
		assertEquals(RefType.UNCONDITIONAL_CALL, i4008.getOperandRefType(0));

		assertEquals(2, i4004.getDefaultFallThroughOffset());
		assertEquals(2, i4008.getDefaultFallThroughOffset());
		assertEquals(b.addr(0x4006), i4004.getDefaultFallThrough());
		assertEquals(b.addr(0x400a), i4008.getDefaultFallThrough());
		assertEquals(b.addr(0x4006), i4004.getFallThrough());
		assertEquals(b.addr(0x400a), i4008.getFallThrough());

		// TODO: Check that cross-language fall-through is properly excluded
		assertNull(i4008.getFallFrom());
		assertEquals(b.addr(0x4004), i4006.getFallFrom());

		assertEquals(5, i4004.getPcode().length);
		assertEquals(2, i4008.getPcode().length);
		assertEquals(5, i4004.getPcode(true).length);
		assertEquals(2, i4008.getPcode(true).length);

		// Boo. This test really tells me nothing
		assertEquals(0, i4004.getPcode(-1).length);
		assertEquals(0, i4004.getPcode(0).length);
		assertEquals(0, i4004.getPcode(1).length);
		assertEquals(0, i4004.getPcode(2).length);

		// TODO: Test in delay slots? I don't think it really pays here....
		assertEquals(0, i4004.getDelaySlotDepth());
		assertEquals(0, i4008.getDelaySlotDepth());
		assertFalse(i4004.isInDelaySlot());
		assertFalse(i4008.isInDelaySlot());

		// TODO: Test with guest language
		assertEquals(Set.of(), set(i4004.getFlows()));
		assertEquals(Set.of(), set(i4004.getDefaultFlows())); // Fall-through excluded
		assertEquals(Set.of(), set(i4008.getFlows())); // TODO: Is this to spec?
		assertEquals(Set.of(b.addr(0x4004)), set(i4008.getDefaultFlows()));

		assertTrue(i4004.isFallthrough());
		assertFalse(i4006.isFallthrough());
		assertFalse(i4008.isFallthrough());

		assertTrue(i4004.hasFallthrough());
		assertFalse(i4006.hasFallthrough());
		assertTrue(i4008.hasFallthrough());

		// Try some mutations
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.addOperandReference(1, b.addr(0x5000), RefType.DATA_IND, SourceType.USER_DEFINED);
			// TODO: This should probably be default for first/only reference
			b.trace.getReferenceManager()
					.getReference(0, b.addr(0x4004), b.addr(0x5000),
						1)
					.setPrimary(true);
		}
		assertEquals(OperandType.ADDRESS | OperandType.SCALAR, i4004.getOperandType(1));
		// NOTE: not DATA_IND, because refType is not sensitive to reference manager.
		// See InstructionDB#getOperandRefType(int)
		assertEquals(RefType.DATA, i4004.getOperandRefType(1));

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setFallThrough(b.addr(0x5000));
		}
		assertEquals(b.addr(0x5000), i4004.getAddress(1));
		assertEquals(b.addr(0x5000), i4004.getFallThrough());
		assertNull(i4006.getFallFrom());
		assertEquals(Set.of(b.addr(0x5000)), set(i4004.getFlows()));
		assertEquals(Set.of(), set(i4004.getDefaultFlows()));

		// TODO: Test FALL_THROUGH mutations via ReferenceManager reflected in Instruction's
		// flowOverride flags. Cannot be done until ReferenceManager is observable by CodeManager.

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.clearFallThroughOverride();
		}
		assertEquals(b.addr(0x4006), i4004.getFallThrough());
		assertEquals(b.addr(0x4004), i4006.getFallFrom());

		try (UndoableTransaction tid = b.startTransaction()) {
			i400a.addMnemonicReference(b.addr(0x6000), RefType.COMPUTED_CALL,
				SourceType.USER_DEFINED);
		}
		assertEquals(Set.of(b.addr(0x6000)), set(i400a.getFlows()));

		try (UndoableTransaction tid = b.startTransaction()) {
			i400a.setFlowOverride(FlowOverride.RETURN);
		}
		assertEquals(Set.of(), set(i400a.getDefaultFlows()));
		TraceReference[] refs = i400a.getMnemonicReferences();
		assertEquals(1, refs.length);
		// TODO: Figure out what would cause setFlowOverride to call setReferenceType
		assertEquals(RefType.COMPUTED_CALL, refs[0].getReferenceType());
	}

	@Test
	public void testInstructionContextSettersGetters()
			throws CodeUnitInsertionException, ContextChangeException {
		Register r4 = b.language.getRegister("r4");
		Register r5 = b.language.getRegister("r5");

		TraceInstruction i4004;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
		}

		// TODO: Test with non-default context
		assertEquals(Register.NO_CONTEXT, i4004.getBaseContextRegister());

		assertEquals(b.language.getRegisters(), i4004.getRegisters());
		assertEquals(r4, i4004.getRegister("r4"));

		assertFalse(i4004.hasValue(r4));
		assertNull(i4004.getValue(r4, true));
		assertNull(i4004.getRegisterValue(r4));

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.clearRegister(r4); // NOP, but cannot crash
		}

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setValue(r4, new BigInteger("ffffffffffff1234", 16));
		}
		assertTrue(i4004.hasValue(r4));
		assertFalse(i4004.hasValue(r5));
		assertEquals(new BigInteger("ffffffffffff1234", 16), i4004.getValue(r4, false));
		assertEquals(new BigInteger("-edcc", 16), i4004.getValue(r4, true));
		assertEquals(new RegisterValue(r4, new BigInteger("ffffffffffff1234", 16)),
			i4004.getRegisterValue(r4));
		assertEquals(new RegisterValue(r4, new BigInteger("-edcc", 16)),
			i4004.getRegisterValue(r4));

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.setRegisterValue(new RegisterValue(r5, new BigInteger("5678", 16)));
		}
		assertTrue(i4004.hasValue(r5));
		assertEquals(new BigInteger("5678", 16), i4004.getValue(r5, false));
		assertEquals(new RegisterValue(r5, new BigInteger("5678", 16)), i4004.getRegisterValue(r5));

		try (UndoableTransaction tid = b.startTransaction()) {
			i4004.clearRegister(r4); // NOP, but cannot crash
		}
		assertFalse(i4004.hasValue(r4));
	}

	@Test
	public void testGetLength() throws CodeUnitInsertionException {
		TraceData d4000;
		TraceInstruction i4004;
		TraceData d4006;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), LongDataType.dataType, b.buf(1, 2, 3, 4));
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
			d4006 = b.addData(0, b.addr(0x4006), PointerDataType.dataType,
				b.buf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00));
		}
		TraceData u3fff = manager.undefinedData().getAt(0, b.addr(0x3fff));

		assertEquals(1, u3fff.getLength());
		// NOTE: These are already checked by toy-builder's add* methods.
		assertEquals(4, d4000.getLength());
		assertEquals(2, i4004.getLength());
		assertEquals(8, d4006.getLength());
	}

	@Test
	public void testDelete() throws CodeUnitInsertionException {
		TraceData d4000;
		TraceInstruction i4004;
		TraceData d4006;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), LongDataType.dataType, b.buf(1, 2, 3, 4));
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
			d4006 = b.addData(0, b.addr(0x4006), PointerDataType.dataType,
				b.buf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00));
		}
		TraceData u400e = manager.undefinedData().getAt(0, b.addr(0x400e));

		try (UndoableTransaction tid = b.startTransaction()) {
			d4000.delete();
			i4004.delete();
		}
		// TODO: Test for events
		try (UndoableTransaction tid = b.startTransaction()) {
			u400e.delete();
			fail();
		}
		catch (UnsupportedOperationException e) {
			// pass
		}

		assertEquals(List.of(d4006), list(manager.definedUnits().get(0, true)));
	}

	@Test
	public void testGetLanguage() throws CodeUnitInsertionException, AddressOverflowException {
		Language x86 = getSLEIGH_X86_LANGUAGE();
		TraceGuestLanguage guest;
		TraceInstruction i4004;
		TraceInstruction g4006;
		try (UndoableTransaction tid = b.startTransaction()) {
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xf4, 0));
			guest = b.trace.getLanguageManager().addGuestLanguage(x86);
			guest.addMappedRange(b.addr(0x0000), b.addr(guest, 0x0000), 1L << 32);
			g4006 = b.addInstruction(0, b.addr(0x4006), x86, b.buf(0x90));
		}
		TraceData u4007 = manager.undefinedData().getAt(0, b.addr(0x4007));

		assertEquals(b.language, i4004.getLanguage());
		assertEquals(x86, g4006.getLanguage());
		assertEquals(b.language, u4007.getLanguage());
	}

	@Test
	public void testToString() throws CodeUnitInsertionException, AddressOverflowException,
			TraceOverlappedRegionException, DuplicateNameException {
		Language x86 = getSLEIGH_X86_LANGUAGE();
		TraceGuestLanguage guest;
		TraceData d4000;
		TraceInstruction i4004;
		TraceInstruction g4006;
		TraceInstruction i4007;
		try (UndoableTransaction tid = b.startTransaction()) {
			// Disassembler's new cacheing in mem-buffer uses program view, so "block" must exist
			b.trace.getMemoryManager()
					.addRegion("myRegion", Range.atLeast(0L),
						b.range(0x4000, 0x4fff), TraceMemoryFlag.READ);

			guest = b.trace.getLanguageManager().addGuestLanguage(x86);
			guest.addMappedRange(b.addr(0x0000), b.addr(guest, 0x0000), 1L << 32);

			d4000 = b.addData(0, b.addr(0x4000), LongDataType.dataType, b.buf(1, 2, 3, 4));
			i4004 = b.addInstruction(0, b.addr(0x4004), b.language, b.buf(0xc8, 0x47));
			g4006 = b.addInstruction(0, b.addr(0x4006), x86, b.buf(0x90));
			i4007 = b.addInstruction(0, b.addr(0x4007), b.language, b.buf(0xff, 0xfd));
		}
		TraceData u4009 = manager.undefinedData().getAt(0, b.addr(0x4009));

		assertEquals("long 1020304h", d4000.toString());
		assertEquals("add r4,#0x7", i4004.toString());
		assertEquals("NOP", g4006.toString());
		assertEquals("call 0x00004004", i4007.toString());
		assertEquals("?? 00h", u4009.toString());
	}

	@Test
	public void testGetDataType() throws CodeUnitInsertionException {
		DataType myTypedef = new TypedefDataType("myTypedef", ShortDataType.dataType);
		TraceData d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), myTypedef, b.buf(1, 2));
		}
		myTypedef = b.trace.getDataTypeManager().getDataType("/myTypedef");
		DataType myShort = b.trace.getDataTypeManager().getDataType("/short");

		assertEquals(myTypedef, d4000.getDataType());
		assertEquals(myShort, d4000.getBaseDataType());
	}

	@Test
	public void testComponentRelatedGetters() throws CodeUnitInsertionException {
		ArrayDataType myNestedArray = new ArrayDataType(ByteDataType.dataType, 2, 1);
		UnionDataType myNestedUnion = new UnionDataType("myNestedUnion");
		myNestedUnion.add(myNestedArray, "naA", null);
		myNestedUnion.add(ShortDataType.dataType, "sB", null);
		StructureDataType myStruct = new StructureDataType("myStruct", 0);
		myStruct.add(ShortDataType.dataType, 2, "sC", null);
		myStruct.add(myNestedUnion, 2, "nuD", null);
		myStruct.add(LongDataType.dataType, 4, "", null); // Default field name by empty
		myStruct.add(PointerDataType.dataType, 8, null, null); // Default field name by null

		TraceData s4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			s4000 = b.addData(0, b.addr(0x4000), myStruct,
				b.buf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16));
		}
		TraceData u3fff = manager.undefinedData().getAt(0, b.addr(0x3fff));

		TraceData s4000nuD = s4000.getComponent(1);
		TraceData s4000naA = s4000nuD.getComponent(0);
		TraceData s4000b0 = s4000naA.getComponent(0);
		TraceData s4000b1 = s4000naA.getComponent(1);
		TraceData s4000lE = s4000.getComponent(2);
		TraceData s4000pF = s4000.getComponent(3);

		assertNull(u3fff.getParent());
		assertNull(s4000.getParent());
		assertEquals(s4000, s4000nuD.getParent());
		assertEquals(s4000nuD, s4000naA.getParent());

		assertEquals(u3fff, u3fff.getRoot());
		assertEquals(s4000, s4000.getRoot());
		assertEquals(s4000, s4000b0.getRoot());

		assertEquals(0, u3fff.getRootOffset());
		assertEquals(0, s4000.getRootOffset());
		assertEquals(2, s4000b0.getRootOffset());
		assertEquals(3, s4000b1.getRootOffset());
		assertEquals(8, s4000pF.getRootOffset());

		assertEquals(0, u3fff.getParentOffset());
		assertEquals(0, s4000.getParentOffset());
		assertEquals(1, s4000b1.getParentOffset());

		assertArrayEquals(new int[] {}, u3fff.getComponentPath());
		assertArrayEquals(new int[] {}, s4000.getComponentPath());
		assertArrayEquals(new int[] { 1, 0, 1 }, s4000b1.getComponentPath());
		// NOTE: A second time to verify coverage of cached result
		assertArrayEquals(new int[] { 1, 0, 1 }, s4000b1.getComponentPath());

		assertEquals(-1, u3fff.getComponentIndex());
		assertEquals(-1, s4000.getComponentIndex());
		assertEquals(1, s4000nuD.getComponentIndex());
		assertEquals(0, s4000naA.getComponentIndex());
		assertEquals(1, s4000b1.getComponentIndex());

		assertEquals(0, u3fff.getComponentLevel());
		assertEquals(0, s4000.getComponentLevel());
		assertEquals(1, s4000nuD.getComponentLevel());
		assertEquals(2, s4000naA.getComponentLevel());
		assertEquals(3, s4000b1.getComponentLevel());

		assertNull(u3fff.getFieldName());
		assertNull(s4000.getFieldName());
		assertEquals("nuD", s4000nuD.getFieldName());
		assertEquals("field2_0x4", s4000lE.getFieldName());
		assertEquals("field3_0x8", s4000pF.getFieldName());

		// TODO: DAT... may change when proper symbols are implemented
		assertEquals("DAT_00003fff", u3fff.getPathName());
		assertEquals("DAT_00004000", s4000.getPathName());
		assertEquals("DAT_00004000.nuD.naA[1]", s4000b1.getPathName());

		assertNull(u3fff.getComponentPathName());
		assertNull(s4000.getComponentPathName());
		// TODO: Determine whether or not leading . is included
		assertEquals(".nuD.naA[1]", s4000b1.getComponentPathName());
	}

	@Test
	public void testComponentProperties() throws Exception {
		Structure myStruct = new StructureDataType("myStruct", 0);
		TypeDef myTypedef = new TypedefDataType("myTypedef", ShortDataType.dataType);
		myStruct.add(ShortDataType.dataType, "sA", null);
		myStruct.add(myTypedef, "tdsB", null);

		TraceThread thread;

		TraceData d4000;
		TraceData dR4;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), myStruct, b.buf(1, 2, 3, 4));

			thread = b.getOrAddThread("Thread 1", 0);
			DBTraceCodeRegisterSpace regCode = manager.getCodeRegisterSpace(thread, true);
			dR4 = regCode.definedData()
					.create(Range.atLeast(0L), b.language.getRegister("r4"),
						myStruct);
		}
		myStruct = (Structure) b.trace.getDataTypeManager().getDataType("/myStruct");
		myTypedef = (TypeDef) b.trace.getDataTypeManager().getDataType("/myTypedef");
		ShortDataType myShort = (ShortDataType) b.trace.getDataTypeManager().getDataType("/short");

		TraceData d4000sB = d4000.getComponent(1);
		TraceData dR4sB = dR4.getComponent(1);

		assertEquals("myTypedef 304h", d4000sB.toString());

		try {
			d4000sB.delete();
			fail();
		}
		catch (UnsupportedOperationException e) {
			// pass
		}

		assertEquals(b.trace, d4000sB.getTrace());

		assertNull(d4000sB.getThread());
		assertEquals(thread, dR4sB.getThread());

		assertEquals(b.language, d4000sB.getLanguage());

		assertEquals(Range.atLeast(0L), d4000sB.getLifespan());

		try {
			dR4sB.setEndSnap(9);
			fail();
		}
		catch (UnsupportedOperationException e) {
			// pass
		}

		assertEquals(0L, d4000sB.getStartSnap());

		assertEquals(b.addr(0x4002), d4000sB.getAddress());
		assertEquals(b.language.getRegister("r4").getAddress().add(3), dR4sB.getMaxAddress());

		assertEquals(2, d4000sB.getLength());

		ByteBuffer buf = ByteBuffer.allocate(4);
		assertEquals(4, d4000sB.getBytes(buf, 0));
		assertArrayEquals(b.arr(3, 4, 0, 0), buf.array());
		buf = ByteBuffer.allocate(1);
		assertEquals(1, d4000sB.getBytes(buf, 1));
		assertArrayEquals(b.arr(4), buf.array());

		assertArrayEquals(b.arr(3, 4), d4000sB.getBytes());

		byte[] bytes = new byte[4];
		d4000sB.getBytesInCodeUnit(bytes, 1);
		assertArrayEquals(b.arr(0, 3, 4, 0), bytes);

		assertSame(myTypedef, d4000sB.getDataType());
		assertSame(myShort, d4000sB.getBaseDataType());

		assertNull(d4000sB.getLong("myLong"));
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000sB.setLong("myLong", 0x1234);
		}
		assertEquals(0x1234, d4000sB.getLong("myLong").longValue());
	}

	@Test
	public void testGetDefaultSettings() throws CodeUnitInsertionException {
		assertNotNull(ByteDataType.dataType.getDefaultSettings());
		TraceData d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), ByteDataType.dataType, b.buf(1));
		}
		DataType byteDataType = b.trace.getDataTypeManager().getDataType("/byte");
		assertSame(byteDataType.getDefaultSettings(), d4000.getDefaultSettings());
	}

	@Test
	public void testSettingsGettersSetters() throws CodeUnitInsertionException {
		DataType myTypedef = new TypedefDataType("myTypedef", LongDataType.dataType);
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceData d4000 = b.addData(0, b.addr(0x4000), myTypedef, b.buf(1, 2, 3, 4));
			TraceData u3fff = manager.undefinedData().getAt(0, b.addr(0x3fff));
			myTypedef = b.trace.getDataTypeManager().getDataType("/myTypedef");

			Settings defs = myTypedef.getDefaultSettings();
			defs.setLong("myDefaultLong", 0x123456789L);
			defs.setString("myDefaultString", "Hello!");
			defs.setByteArray("myDefaultBytes", new byte[] { 4, 3, 2, 1 });

			assertTrue(d4000.isEmpty()); // This is a terribly counter-intuitive method name
			assertArrayEquals(new String[] {}, d4000.getNames());

			u3fff.clearSetting("noSetting"); // Just ensure it doesn't crash
			u3fff.clearAllSettings();
			d4000.clearSetting("noSetting");
			d4000.clearAllSettings();

			assertNull(u3fff.getLong("myLong"));
			assertNull(d4000.getLong("myLong"));
			assertNull(d4000.getString("myString"));
			assertNull(d4000.getByteArray("myBytes"));
			assertNull(d4000.getValue("myLong"));
			assertFalse(d4000.isConstant());
			assertFalse(d4000.isVolatile());

			assertEquals(0x123456789L, d4000.getLong("myDefaultLong").longValue());
			assertEquals("Hello!", d4000.getString("myDefaultString"));
			assertArrayEquals(new byte[] { 4, 3, 2, 1 }, d4000.getByteArray("myDefaultBytes"));
			assertEquals("Hello!", d4000.getValue("myDefaultString"));

			d4000.setLong("myLong", Long.MAX_VALUE);
			d4000.setString("myString", "Good bye!");
			d4000.setByteArray("myBytes", new byte[] { 8, 7, 6, 5 });

			assertFalse(d4000.isEmpty());
			// TODO: Figure out whether or not this includes defaultSettings?
			assertEquals(Set.of("myLong", "myString", "myBytes"), set(d4000.getNames()));

			d4000.setLong("myDefaultLong", Long.MAX_VALUE);
			d4000.setString("myDefaultString", "Good bye!");
			d4000.setValue("myDefaultBytes", new byte[] { 8, 7, 6, 5 }); // Swap one for Value

			assertEquals(Long.MAX_VALUE, d4000.getLong("myLong").longValue());
			assertEquals("Good bye!", d4000.getString("myString"));
			assertArrayEquals(new byte[] { 8, 7, 6, 5 }, d4000.getByteArray("myBytes"));
			assertArrayEquals(new byte[] { 8, 7, 6, 5 }, (byte[]) d4000.getValue("myBytes"));

			assertEquals(Long.MAX_VALUE, d4000.getLong("myDefaultLong").longValue());
			assertEquals("Good bye!", d4000.getString("myDefaultString"));
			assertArrayEquals(new byte[] { 8, 7, 6, 5 }, d4000.getByteArray("myDefaultBytes"));

			d4000.clearSetting("myDefaultLong");
			assertEquals(0x123456789L, d4000.getLong("myDefaultLong").longValue());
			assertEquals(Long.valueOf(0x123456789L), d4000.getValue("myDefaultLong"));
			assertEquals("Good bye!", d4000.getString("myDefaultString")); // Check unaffected

			d4000.clearAllSettings();
			assertTrue(d4000.isEmpty());

			assertNull(d4000.getLong("myLong"));
			assertNull(d4000.getString("myString"));
			assertNull(d4000.getByteArray("myBytes"));

			assertEquals(0x123456789L, d4000.getLong("myDefaultLong").longValue());
			assertEquals("Hello!", d4000.getString("myDefaultString"));
			assertArrayEquals(new byte[] { 4, 3, 2, 1 }, d4000.getByteArray("myDefaultBytes"));
			assertNull(d4000.getValue("myLong"));

			assertFalse(d4000.isConstant());
			assertFalse(d4000.isVolatile());

			MutabilitySettingsDefinition.DEF.setChoice(d4000,
				MutabilitySettingsDefinition.CONSTANT);
			assertTrue(d4000.isConstant());
			assertFalse(d4000.isVolatile());

			MutabilitySettingsDefinition.DEF.setChoice(d4000,
				MutabilitySettingsDefinition.VOLATILE);
			assertFalse(d4000.isConstant());
			assertTrue(d4000.isVolatile());

			MutabilitySettingsDefinition.DEF.setChoice(d4000, MutabilitySettingsDefinition.NORMAL);
			assertFalse(d4000.isConstant());
			assertFalse(d4000.isVolatile());
		}
	}

	@Test
	public void testGetNumOperands() throws CodeUnitInsertionException {
		TraceData d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), LongDataType.dataType, b.buf(1, 2, 3, 4));
		}

		assertEquals(1, d4000.getNumOperands());
	}

	@Test
	public void testIsDefined() throws CodeUnitInsertionException {
		TraceData d4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			d4000 = b.addData(0, b.addr(0x4000), LongDataType.dataType, b.buf(1, 2, 3, 4));
		}
		TraceData u3fff = manager.undefinedData().getAt(0, b.addr(0x3fff));

		assertFalse(u3fff.isDefined());
		assertTrue(d4000.isDefined());
	}

	protected Set<TraceData> comps(TraceData data, int... indices) {
		Set<TraceData> result = new HashSet<>();
		for (int i : indices) {
			result.add(data.getComponent(i));
		}
		return result;
	}

	@Test
	public void testComponentGetters() throws CodeUnitInsertionException,
			TraceOverlappedRegionException, DuplicateNameException, InvalidDataTypeException {
		Structure myStruct = new StructureDataType("myStruct", 0);
		myStruct.add(ShortDataType.dataType);
		myStruct.add(ShortDataType.dataType);
		myStruct.insertBitFieldAt(4, 1, 0, ByteDataType.dataType, 1, "bf1", null);
		myStruct.insertBitFieldAt(4, 1, 1, ByteDataType.dataType, 3, "bf2", null);
		myStruct.insertBitFieldAt(4, 1, 4, ByteDataType.dataType, 2, "bf3", null);
		myStruct.insertBitFieldAt(4, 1, 6, ByteDataType.dataType, 2, "bf4", null);

		Union myUnion = new UnionDataType("myUnion");
		myUnion.add(LongDataType.dataType);
		myUnion.add(ShortDataType.dataType);

		Array myArray = new ArrayDataType(ByteDataType.dataType, 4, 1);

		TraceData d4000;
		TraceData d4004;
		TraceData d400c;
		TraceData d401c;
		TraceData d4020;
		try (UndoableTransaction tid = b.startTransaction()) {
			// StringDataType accesses memory via program view, so "block" must exist
			b.trace.getMemoryManager()
					.addRegion("myRegion", Range.atLeast(0L),
						b.range(0x4000, 0x4fff), TraceMemoryFlag.READ);

			d4000 = b.addData(0, b.addr(0x4000), LongDataType.dataType, b.buf(1, 2, 3, 4));
			d4004 = b.addData(0, b.addr(0x4004), myStruct, b.buf(5, 6, 7, 8, 9));
			// 3-byte gap
			d400c = b.addData(0, b.addr(0x400c), new RepeatedStringDataType(), b.buf(0, 3, //
				't', 'i', 'c', 0, //
				't', 'a', 'c', 0, //
				't', 'o', 'e', 0));
			// 2-byte gap
			d401c = b.addData(0, b.addr(0x401c), myUnion, b.buf(9, 10, 11, 12));
			d4020 = b.addData(0, b.addr(0x4020), myArray, b.buf(13, 14, 15, 16));
		}
		TraceData u3fff = manager.undefinedData().getAt(0, b.addr(0x3fff));

		assertEquals(0, u3fff.getNumComponents());
		assertEquals(0, d4000.getNumComponents());
		assertEquals(6, d4004.getNumComponents());
		assertEquals(4, d400c.getNumComponents());
		assertEquals(2, d401c.getNumComponents());
		assertEquals(4, d4020.getNumComponents());

		assertNull(u3fff.getComponent(0));
		assertNull(d4000.getComponent(0));

		assertNull(d4004.getComponent(-1));
		assertNull(d4004.getComponent(6));

		assertEquals(d4004.getComponent(0), d4004.getComponent(0)); // Testing cache

		assertEquals(new Scalar(16, 3), d400c.getComponent(0).getValue());
		assertEquals("tic", d400c.getComponent(1).getValue());
		assertEquals("tac", d400c.getComponent(2).getValue());
		assertEquals("toe", d400c.getComponent(3).getValue());

		assertNull(u3fff.getComponentAt(0));
		assertNull(d4000.getComponentAt(0));

		assertNull(d4004.getComponentAt(-1));
		assertEquals(d4004.getComponent(0), d4004.getComponentAt(0));
		assertEquals(d4004.getComponent(0), d4004.getComponentAt(1));
		assertEquals(d4004.getComponent(1), d4004.getComponentAt(2));
		assertEquals(d4004.getComponent(1), d4004.getComponentAt(3));
		assertEquals(d4004.getComponent(2), d4004.getComponentAt(4));
		assertNull(d4004.getComponentAt(5));

		assertEquals(d400c.getComponent(0), d400c.getComponentAt(0));
		assertEquals(d400c.getComponent(0), d400c.getComponentAt(1));
		assertEquals(d400c.getComponent(1), d400c.getComponentAt(2));
		assertEquals(d400c.getComponent(1), d400c.getComponentAt(3));
		assertEquals(d400c.getComponent(1), d400c.getComponentAt(4));
		assertEquals(d400c.getComponent(1), d400c.getComponentAt(5));
		assertEquals(d400c.getComponent(2), d400c.getComponentAt(6));
		assertEquals(d400c.getComponent(2), d400c.getComponentAt(7));
		assertEquals(d400c.getComponent(2), d400c.getComponentAt(8));
		assertEquals(d400c.getComponent(2), d400c.getComponentAt(9));
		assertEquals(d400c.getComponent(3), d400c.getComponentAt(10));
		assertEquals(d400c.getComponent(3), d400c.getComponentAt(11));
		assertEquals(d400c.getComponent(3), d400c.getComponentAt(12));
		assertEquals(d400c.getComponent(3), d400c.getComponentAt(13));

		assertNull(d401c.getComponentAt(0));
		assertNull(d401c.getComponentAt(1));
		assertNull(d401c.getComponentAt(2));
		assertNull(d401c.getComponentAt(3));

		assertEquals(d4020.getComponent(0), d4020.getComponentAt(0));
		assertEquals(d4020.getComponent(1), d4020.getComponentAt(1));
		assertEquals(d4020.getComponent(2), d4020.getComponentAt(2));
		assertEquals(d4020.getComponent(3), d4020.getComponentAt(3));

		assertNull(u3fff.getComponentsContaining(-1));
		assertTrue(u3fff.getComponentsContaining(0).isEmpty());
		assertNull(u3fff.getComponentsContaining(1));

		assertNull(d4000.getComponentsContaining(-1));
		assertTrue(d4000.getComponentsContaining(0).isEmpty());
		assertNull(d4000.getComponentsContaining(4));

		assertEquals(comps(d4004, 0), set(d4004.getComponentsContaining(0)));
		assertEquals(comps(d4004, 0), set(d4004.getComponentsContaining(1)));
		assertEquals(comps(d4004, 1), set(d4004.getComponentsContaining(2)));
		assertEquals(comps(d4004, 1), set(d4004.getComponentsContaining(3)));
		assertEquals(comps(d4004, 2, 3, 4, 5), set(d4004.getComponentsContaining(4)));

		assertEquals(comps(d400c, 0), set(d400c.getComponentsContaining(0)));
		assertEquals(comps(d400c, 0), set(d400c.getComponentsContaining(1)));
		assertEquals(comps(d400c, 1), set(d400c.getComponentsContaining(2)));
		assertEquals(comps(d400c, 1), set(d400c.getComponentsContaining(3)));
		assertEquals(comps(d400c, 1), set(d400c.getComponentsContaining(4)));
		assertEquals(comps(d400c, 1), set(d400c.getComponentsContaining(5)));
		assertEquals(comps(d400c, 2), set(d400c.getComponentsContaining(6)));
		assertEquals(comps(d400c, 2), set(d400c.getComponentsContaining(7)));
		assertEquals(comps(d400c, 2), set(d400c.getComponentsContaining(8)));
		assertEquals(comps(d400c, 2), set(d400c.getComponentsContaining(9)));
		assertEquals(comps(d400c, 3), set(d400c.getComponentsContaining(10)));
		assertEquals(comps(d400c, 3), set(d400c.getComponentsContaining(11)));
		assertEquals(comps(d400c, 3), set(d400c.getComponentsContaining(12)));
		assertEquals(comps(d400c, 3), set(d400c.getComponentsContaining(13)));

		assertEquals(comps(d401c, 0, 1), set(d401c.getComponentsContaining(0)));
		assertEquals(comps(d401c, 0, 1), set(d401c.getComponentsContaining(1)));
		assertEquals(comps(d401c, 0), set(d401c.getComponentsContaining(2)));
		assertEquals(comps(d401c, 0), set(d401c.getComponentsContaining(3)));

		assertEquals(comps(d4020, 0), set(d4020.getComponentsContaining(0)));
		assertEquals(comps(d4020, 1), set(d4020.getComponentsContaining(1)));
		assertEquals(comps(d4020, 2), set(d4020.getComponentsContaining(2)));
		assertEquals(comps(d4020, 3), set(d4020.getComponentsContaining(3)));
	}

	@Test
	public void testNestedComponentGetters() throws CodeUnitInsertionException {
		// Unfortunately, the implementation cannot proceed into a Union
		// Until there is a getPrimitivesContaining(), I suppose....
		ArrayDataType myNestedArray = new ArrayDataType(ByteDataType.dataType, 2, 1);
		StructureDataType myStruct = new StructureDataType("myStruct", 0);
		myStruct.add(ShortDataType.dataType, 2, "sA", null);
		myStruct.add(myNestedArray, 2, "naB", null);
		myStruct.add(LongDataType.dataType, 4, "lC", null);

		TraceData s4000;
		try (UndoableTransaction tid = b.startTransaction()) {
			s4000 = b.addData(0, b.addr(0x4000), myStruct, b.buf(1, 2, 3, 4, 5, 6, 7, 8));
		}
		TraceData u3fff = manager.undefinedData().getAt(0, b.addr(0x3fff));
		TraceData s4000sA = s4000.getComponent(0);
		TraceData s4000naB = s4000.getComponent(1);
		TraceData s4000naB0 = s4000naB.getComponent(0);
		TraceData s4000naB1 = s4000naB.getComponent(1);
		TraceData s4000lC = s4000.getComponent(2);

		assertNull(u3fff.getPrimitiveAt(-1));
		assertEquals(u3fff, u3fff.getPrimitiveAt(0));
		assertNull(u3fff.getPrimitiveAt(1));

		assertNull(s4000.getPrimitiveAt(-1));
		assertEquals(s4000sA, s4000.getPrimitiveAt(0));
		assertEquals(s4000sA, s4000.getPrimitiveAt(1));
		assertEquals(s4000naB0, s4000.getPrimitiveAt(2));
		assertEquals(s4000naB1, s4000.getPrimitiveAt(3));
		assertEquals(s4000lC, s4000.getPrimitiveAt(4));
		assertEquals(s4000lC, s4000.getPrimitiveAt(5));
		assertEquals(s4000lC, s4000.getPrimitiveAt(6));
		assertEquals(s4000lC, s4000.getPrimitiveAt(7));
		assertNull(s4000.getPrimitiveAt(8));

		assertEquals(u3fff, u3fff.getComponent(null));
		assertEquals(u3fff, u3fff.getComponent(new int[] {}));
		assertEquals(s4000, s4000.getComponent(null));
		assertEquals(s4000, s4000.getComponent(new int[] {}));

		assertNull(u3fff.getComponent(new int[] { 0 }));
		assertEquals(s4000sA, s4000.getComponent(new int[] { 0 }));
		assertEquals(s4000naB, s4000.getComponent(new int[] { 1 }));
		assertEquals(s4000lC, s4000.getComponent(new int[] { 2 }));

		assertEquals(s4000naB0, s4000.getComponent(new int[] { 1, 0 }));
		assertEquals(s4000naB1, s4000.getComponent(new int[] { 1, 1 }));

		assertNull(s4000.getComponent(new int[] { -1 }));
		assertNull(s4000.getComponent(new int[] { -1, 0 }));
		assertNull(s4000.getComponent(new int[] { 0, -1 }));
		assertNull(s4000.getComponent(new int[] { 0, 0 }));
		assertNull(s4000.getComponent(new int[] { 1, -1, 0 }));
		assertNull(s4000.getComponent(new int[] { 1, 1, 0 }));
	}
}
