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
package ghidra.trace.database.symbol;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.Set;

import org.junit.*;

import db.Transaction;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.symbol.*;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

public class DBTraceReferenceManagerTest extends AbstractGhidraHeadlessIntegrationTest {
	protected static class DummyTraceReference implements TraceReference {
		protected final Lifespan lifespan;
		protected final Address fromAddress;
		protected final AddressRange toRange;

		public DummyTraceReference(long startSnap, Address fromAddress, AddressRange toRange) {
			this.lifespan = Lifespan.nowOn(startSnap);
			this.fromAddress = fromAddress;
			this.toRange = toRange;
		}

		@Override
		public Address getFromAddress() {
			return fromAddress;
		}

		@Override
		public AddressRange getToRange() {
			return toRange;
		}

		@Override
		public boolean isPrimary() {
			return false;
		}

		@Override
		public long getSymbolID() {
			return 0;
		}

		@Override
		public RefType getReferenceType() {
			return RefType.DATA;
		}

		@Override
		public int getOperandIndex() {
			return -1;
		}

		@Override
		public SourceType getSource() {
			return SourceType.DEFAULT;
		}

		@Override
		public Trace getTrace() {
			return null;
		}

		@Override
		public Lifespan getLifespan() {
			return lifespan;
		}

		@Override
		public long getStartSnap() {
			return lifespan.lmin();
		}

		@Override
		public void setPrimary(boolean primary) {
			fail();
		}

		@Override
		public void setReferenceType(RefType refType) {
			fail();
		}

		@Override
		public void setAssociatedSymbol(Symbol symbol) {
			fail();
		}

		@Override
		public void clearAssociatedSymbol() {
			fail();
		}

		@Override
		public void delete() {
			fail();
		}
	}

	protected static class DummyTraceOffsetReference extends DummyTraceReference
			implements TraceOffsetReference {
		protected final long offset;
		protected final Address baseAddress;

		public DummyTraceOffsetReference(long startSnap, Address fromAddress, Address toAddress,
				long offset) {
			super(startSnap, fromAddress, new AddressRangeImpl(toAddress, toAddress));
			this.offset = offset;
			// NOTE: intended for test use in the absence of any EXTERNAL memory block concern
			this.baseAddress = toAddress.subtract(offset);
		}

		@Override
		public long getOffset() {
			return offset;
		}

		@Override
		public Address getBaseAddress() {
			return baseAddress;
		}
	}

	protected static class DummyTraceShiftedReference extends DummyTraceReference
			implements TraceShiftedReference {
		protected final int shift;
		protected final long value;

		public DummyTraceShiftedReference(long startSnap, Address fromAddress, Address toAddress,
				int shift) {
			super(startSnap, fromAddress, new AddressRangeImpl(toAddress, toAddress));
			this.shift = shift;
			this.value = toAddress.getOffset() >>> shift;
		}

		@Override
		public int getShift() {
			return shift;
		}

		@Override
		public long getValue() {
			return value;
		}
	}

	protected ToyDBTraceBuilder b;
	protected DBTraceReferenceManager manager;

	@Before
	public void setUpTraceReferenceManagerTest() throws IOException {
		b = new ToyDBTraceBuilder("Testing", "Toy:BE:64:default");
		manager = b.trace.getReferenceManager();
	}

	@After
	public void tearDownTraceReferenceManagerTest() {
		b.close();
	}

	@Test
	public void testAddReference() {
		DBTraceReference memRef;
		DBTraceReference offRef;
		DBTraceReference sftRef;
		try (Transaction tx = b.startTransaction()) {
			memRef = manager.addReference(
				new DummyTraceReference(0, b.addr(0x4000), b.range(0x5000, 0x5003)));
			offRef = manager.addReference(
				new DummyTraceOffsetReference(0, b.addr(0x4001), b.addr(0x5001), 20));
			sftRef = manager.addReference(
				new DummyTraceShiftedReference(0, b.addr(0x4002), b.addr(0x5002), 1));
		}

		assertNotNull(memRef);
		assertTrue(offRef instanceof DBTraceOffsetReference);
		assertTrue(sftRef instanceof DBTraceShiftedReference);

		assertEquals(b.addr(0x4000), memRef.getFromAddress());
		assertEquals(b.range(0x5000, 0x5003), memRef.getToRange());
		assertEquals(b.addr(0x5000), memRef.getToAddress());

		assertEquals(b.addr(0x4001), offRef.getFromAddress());
		assertEquals(b.addr(0x5001), offRef.getToAddress());
		assertEquals(20, ((DBTraceOffsetReference) offRef).getOffset());
		assertEquals(b.addr(0x4fed), ((DBTraceOffsetReference) offRef).getBaseAddress());

		assertEquals(b.addr(0x4002), sftRef.getFromAddress());
		assertEquals(b.addr(0x5002), sftRef.getToAddress());
		assertEquals(1, ((DBTraceShiftedReference) sftRef).getShift());
		assertEquals(0x2801, ((DBTraceShiftedReference) sftRef).getValue());
	}

	@Test
	public void testAddMemoryReference() {
		try (Transaction tx = b.startTransaction()) {
			b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003));
		}
		DBTraceReferenceSpace space =
			manager.getReferenceSpace(b.language.getDefaultDataSpace(), false);
		assertNotNull(space);
		assertEquals(1, space.referenceMapSpace.size());
		assertEquals(1, space.xrefMapSpace.size());
	}

	@Test
	public void testAddOffsetReference() {
		try (Transaction tx = b.startTransaction()) {
			b.addOffsetReference(0, b.addr(0x4001), b.addr(0x5001), false, 20);
		}
		DBTraceReferenceSpace space =
			manager.getReferenceSpace(b.language.getDefaultDataSpace(), false);
		assertNotNull(space);
		assertEquals(1, space.referenceMapSpace.size());
		assertEquals(1, space.xrefMapSpace.size());
	}

	@Test
	public void testAddShiftedReference() {
		try (Transaction tx = b.startTransaction()) {
			b.addShiftedReference(0, b.addr(0x4002), b.addr(0x5002), 1);
		}
		DBTraceReferenceSpace space =
			manager.getReferenceSpace(b.language.getDefaultDataSpace(), false);
		assertNotNull(space);
		assertEquals(1, space.referenceMapSpace.size());
		assertEquals(1, space.xrefMapSpace.size());
	}

	@Test
	public void testAddRegisterReference() {
		try (Transaction tx = b.startTransaction()) {
			b.addRegisterReference(0, b.addr(0x4003), "r5");
		}
		DBTraceReferenceSpace space =
			manager.getReferenceSpace(b.language.getDefaultDataSpace(), false);
		assertNotNull(space);
		assertEquals(1, space.referenceMapSpace.size());
		assertEquals(0, space.xrefMapSpace.size());
	}

	@Test
	public void testAddStackReference() {
		try (Transaction tx = b.startTransaction()) {
			b.addStackReference(0, b.addr(0x4004), 0x20);
		}
		DBTraceReferenceSpace space =
			manager.getReferenceSpace(b.language.getDefaultDataSpace(), false);
		assertNotNull(space);
		assertEquals(1, space.referenceMapSpace.size());
		assertEquals(0, space.xrefMapSpace.size());
	}

	@Test
	public void testGetReference() {
		DBTraceReference memRef;
		DBTraceReference offRef;
		DBTraceReference sftRef;
		DBTraceReference regRef;
		DBTraceReference stkRef;
		try (Transaction tx = b.startTransaction()) {
			memRef = b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003));
			offRef = b.addOffsetReference(0, b.addr(0x4001), b.addr(0x5001), false, 20);
			sftRef = b.addShiftedReference(0, b.addr(0x4002), b.addr(0x5002), 1);
			regRef = b.addRegisterReference(0, b.addr(0x4003), "r5");
			stkRef = b.addStackReference(0, b.addr(0x4004), 0x20);
		}

		assertNull(manager.getReference(0, b.addr(0x4000), b.addr(0x5000), 0));
		assertNull(manager.getReference(0, b.addr(0x4000), b.range(0x5000, 0x5003), 0));
		assertNull(manager.getReference(0, b.addr(0x4000), b.addr(0x5001), -1));
		assertNull(manager.getReference(0, b.addr(0x4001), b.addr(0x5000), -1));
		assertNull(manager.getReference(-1, b.addr(0x4000), b.addr(0x5000), -1));
		assertEquals(memRef, manager.getReference(0, b.addr(0x4000), b.range(0x5000, 0x5003), -1));
		assertEquals(memRef, manager.getReference(10, b.addr(0x4000), b.range(0x5000, 0x5003), -1));

		assertEquals(offRef, manager.getReference(0, b.addr(0x4001), b.addr(0x5001), -1));

		assertEquals(sftRef, manager.getReference(0, b.addr(0x4002), b.addr(0x5002), -1));

		assertEquals(regRef, manager.getReference(0, b.addr(0x4003),
			TraceRegisterUtils.rangeForRegister(b.language.getRegister("r5")), -1));
		assertNull(manager.getReference(0, b.addr(0x4003),
			TraceRegisterUtils.rangeForRegister(b.language.getRegister("r6")), -1));

		// TODO: A better way to manage the compiler spec
		assertEquals(stkRef, manager.getReference(0, b.addr(0x4004),
			b.language.getDefaultCompilerSpec().getStackSpace().getAddress(0x20), -1));
		assertNull(manager.getReference(0, b.addr(0x4004),
			b.language.getDefaultCompilerSpec().getStackSpace().getAddress(0x21), -1));
	}

	@Test
	public void testGetReferencesFrom() {
		DBTraceReference memRef;
		DBTraceReference offRef;
		DBTraceReference sftRef;
		DBTraceReference regRef;
		DBTraceReference stkRef;
		try (Transaction tx = b.startTransaction()) {
			memRef = b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003), 3);
			offRef = b.addOffsetReference(0, b.addr(0x4000), b.addr(0x5001), false, 20);
			sftRef = b.addShiftedReference(0, b.addr(0x4000), b.addr(0x5002), 1);
			regRef = b.addRegisterReference(0, b.addr(0x4000), "r5");
			stkRef = b.addStackReference(0, b.addr(0x4000), 0x20);

			b.addMemoryReference(0, b.addr(0x4001), b.range(0x8000, 0x8003));
		}

		assertEquals(Set.of(memRef, offRef, sftRef, regRef, stkRef),
			Set.copyOf(manager.getReferencesFrom(0, b.addr(0x4000))));
		assertEquals(Set.of(memRef),
			Set.copyOf(manager.getReferencesFrom(0, b.addr(0x4000), 3)));
		assertEquals(Set.of(offRef, sftRef, regRef, stkRef),
			Set.copyOf(manager.getReferencesFrom(0, b.addr(0x4000), -1)));
	}

	@Test
	public void testFromToIndexUnique() {
		DBTraceReference at0;
		DBTraceReference at10;
		DBTraceReference diffFrom;
		DBTraceReference diffTo;
		DBTraceReference diffOpIndex;
		try (Transaction tx = b.startTransaction()) {
			at0 = b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003), 0);
			b.addMemoryReference(15, b.addr(0x4000), b.range(0x5000, 0x5003), 0); // Lost
			at10 = b.addMemoryReference(10, b.addr(0x4000), b.range(0x5000, 0x5003), 0);

			diffFrom = b.addMemoryReference(0, b.addr(0x4001), b.range(0x5000, 0x5003), 0);
			diffTo = b.addMemoryReference(0, b.addr(0x4000), b.range(0x5004, 0x5007), 0);
			diffOpIndex = b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003), 1);

			assertEquals(Set.of(at0, diffTo, diffOpIndex),
				Set.copyOf(manager.getReferencesFrom(0, b.addr(0x4000))));
			assertEquals(Set.of(at10, diffTo, diffOpIndex),
				Set.copyOf(manager.getReferencesFrom(15, b.addr(0x4000))));

			assertEquals(Set.of(diffFrom),
				Set.copyOf(manager.getReferencesFrom(0, b.addr(0x4001))));
			assertEquals(Set.of(diffFrom),
				Set.copyOf(manager.getReferencesFrom(15, b.addr(0x4001))));
		}
	}

	@Test
	public void testGetPrimaryReferenceFrom() {
		// TODO: Test this against ReferenceDBManager
		// Seems it might make first added reference primary.
		// TODO: See how ReferenceDBManager select new primary on deletion
		DBTraceReference memRef;
		DBTraceReference offRef;
		try (Transaction tx = b.startTransaction()) {
			memRef = b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003));
			offRef = b.addOffsetReference(0, b.addr(0x4000), b.addr(0x5001), false, 20);

			assertNull(manager.getPrimaryReferenceFrom(0, b.addr(0x4000), -1));

			memRef.setPrimary(true);
			assertTrue(memRef.isPrimary());

			assertEquals(memRef, manager.getPrimaryReferenceFrom(0, b.addr(0x4000), -1));
			assertNull(manager.getPrimaryReferenceFrom(0, b.addr(0x4000), 3));

			offRef.setPrimary(true);
			assertTrue(offRef.isPrimary());
			assertFalse(memRef.isPrimary());
			assertEquals(offRef, manager.getPrimaryReferenceFrom(0, b.addr(0x4000), -1));
		}
	}

	@Test
	public void testGetFlowReferencesFrom() {
		TraceReference flowRef;
		try (Transaction tx = b.startTransaction()) {
			flowRef = manager.addMemoryReference(Lifespan.nowOn(0), b.addr(0x4000), b.addr(0x4001),
				RefType.FLOW, SourceType.DEFAULT, -1);
			b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003));
			b.addOffsetReference(0, b.addr(0x4000), b.addr(0x5001), false, 20);
		}

		assertEquals(Set.of(flowRef),
			Set.copyOf(manager.getFlowReferencesFrom(0, b.addr(0x4000))));
	}

	@Test
	public void testClearReferencesFrom() {
		DBTraceReference keptRef;
		try (Transaction tx = b.startTransaction()) {
			b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003), 3);
			b.addOffsetReference(0, b.addr(0x4000), b.addr(0x5001), false, 20);
			b.addShiftedReference(0, b.addr(0x4000), b.addr(0x5002), 1);
			b.addRegisterReference(0, b.addr(0x4000), "r5");
			b.addStackReference(0, b.addr(0x4000), 0x20);
			keptRef = b.addMemoryReference(0, b.addr(0x4001), b.range(0x8000, 0x8003));
		}

		assertEquals(5, manager.getReferencesFrom(0, b.addr(0x4000)).size());
		assertEquals(1, manager.getReferencesFrom(0, b.addr(0x4001)).size());

		try (Transaction tx = b.startTransaction()) {
			manager.clearReferencesFrom(Lifespan.nowOn(10), b.range(0x3000, 0x4000));
		}

		assertEquals(5, manager.getReferencesFrom(0, b.addr(0x4000)).size());
		assertEquals(0, manager.getReferencesFrom(10, b.addr(0x4000)).size());
		assertEquals(Lifespan.span(0, 9),
			manager.getReferencesFrom(0, b.addr(0x4000)).iterator().next().getLifespan());

		try (Transaction tx = b.startTransaction()) {
			manager.clearReferencesFrom(Lifespan.nowOn(0), b.range(0x3000, 0x4000));
		}

		assertEquals(0, manager.getReferencesFrom(0, b.addr(0x4000)).size());
		assertEquals(0, manager.getReferencesFrom(-1, b.addr(0x4000)).size());
		assertEquals(1, manager.getReferencesFrom(0, b.addr(0x4001)).size());
		assertEquals(keptRef, manager.getReferencesFrom(0, b.addr(0x4001)).iterator().next());
		assertEquals(Lifespan.nowOn(0), keptRef.getLifespan());
	}

	@Test
	public void testGetReferencesTo() {
		DBTraceReference memRef;
		DBTraceReference offRef;
		DBTraceReference sftRef;
		try (Transaction tx = b.startTransaction()) {
			memRef = b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003));
			offRef = b.addOffsetReference(0, b.addr(0x4001), b.addr(0x5000), false, 20);
			sftRef = b.addShiftedReference(0, b.addr(0x4002), b.addr(0x5000), 1);
			b.addRegisterReference(0, b.addr(0x4003), "r5");
			b.addStackReference(0, b.addr(0x4004), 0x20);

			b.addMemoryReference(0, b.addr(0x4005), b.range(0x8000, 0x8003));
		}

		assertEquals(Set.of(memRef, offRef, sftRef),
			Set.copyOf(manager.getReferencesTo(0, b.addr(0x5000))));
	}

	@Test
	public void tesGetReferencesToRange() {
		DBTraceReference memRef1;
		DBTraceReference memRef2;
		DBTraceReference memRef3;
		try (Transaction tx = b.startTransaction()) {
			memRef1 = b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003));
			memRef2 = b.addMemoryReference(5, b.addr(0x4000), b.range(0x5002, 0x5005));
			memRef3 = b.addMemoryReference(0, b.addr(0x4000), b.range(0x5004, 0x5007));
		}

		assertEquals(Set.of(memRef1, memRef2, memRef3),
			Set.copyOf(manager.getReferencesToRange(Lifespan.nowOn(0), b.range(0x5000, 0x5007))));
		assertEquals(Set.of(memRef1),
			Set.copyOf(manager.getReferencesToRange(Lifespan.nowOn(0), b.range(0x5000, 0x5000))));
		assertEquals(Set.of(memRef1, memRef3),
			Set.copyOf(manager.getReferencesToRange(Lifespan.at(0), b.range(0x5000, 0x5007))));
	}

	@Test
	public void testClearReferencesTo() {
		DBTraceReference keptRef;
		try (Transaction tx = b.startTransaction()) {
			b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003), 3);
			b.addOffsetReference(0, b.addr(0x4001), b.addr(0x5000), false, 20);
			b.addShiftedReference(0, b.addr(0x4002), b.addr(0x5000), 1);
			keptRef = b.addMemoryReference(0, b.addr(0x8000), b.range(0x5004, 0x5007));
		}

		assertEquals(3, manager.getReferencesTo(0, b.addr(0x5000)).size());
		assertEquals(1, manager.getReferencesTo(0, b.addr(0x5001)).size());

		try (Transaction tx = b.startTransaction()) {
			manager.clearReferencesTo(Lifespan.nowOn(10), b.range(0x4000, 0x5000));
		}

		assertEquals(3, manager.getReferencesTo(0, b.addr(0x5000)).size());
		assertEquals(0, manager.getReferencesTo(10, b.addr(0x5000)).size());
		assertEquals(Lifespan.span(0, 9),
			manager.getReferencesTo(0, b.addr(0x5000)).iterator().next().getLifespan());

		try (Transaction tx = b.startTransaction()) {
			manager.clearReferencesTo(Lifespan.nowOn(0), b.range(0x4000, 0x5000));
		}

		assertEquals(0, manager.getReferencesTo(0, b.addr(0x5000)).size());
		assertEquals(0, manager.getReferencesTo(-1, b.addr(0x5000)).size());
		assertEquals(1, manager.getReferencesTo(0, b.addr(0x5004)).size());
		assertEquals(keptRef, manager.getReferencesTo(0, b.addr(0x5004)).iterator().next());
		assertEquals(Lifespan.nowOn(0), keptRef.getLifespan());
	}

	@Test
	public void testGetReferenceSourcesAndDestinations() {
		try (Transaction tx = b.startTransaction()) {
			b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5000));
			b.addOffsetReference(0, b.addr(0x4001), b.addr(0x5001), false, 20);
			b.addShiftedReference(0, b.addr(0x4002), b.addr(0x5002), 1);
			b.addRegisterReference(0, b.addr(0x4003), "r5");
			b.addStackReference(0, b.addr(0x4004), 0x20);
			b.addMemoryReference(0, b.addr(0x4005), b.range(0x8000, 0x8003));
		}

		assertEquals(b.set(b.range(0x4000, 0x4005)),
			manager.getReferenceSources(Lifespan.span(0, 0)));
		assertEquals(b.set(), manager.getReferenceSources(Lifespan.span(-1, -1)));
		assertEquals(b.set(b.range(0x5000, 0x5002), b.range(0x8000, 0x8003)),
			manager.getReferenceDestinations(Lifespan.span(0, 0)));
		assertEquals(b.set(), manager.getReferenceDestinations(Lifespan.span(-1, -1)));
	}

	@Test
	public void testGetReferenceCounts() {
		assertEquals(0, manager.getReferenceCountFrom(0, b.addr(0x4000)));
		assertEquals(0, manager.getReferenceCountTo(0, b.addr(0x5000)));

		try (Transaction tx = b.startTransaction()) {
			b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003));
			b.addOffsetReference(0, b.addr(0x4000), b.addr(0x5001), false, 20);
			b.addShiftedReference(0, b.addr(0x4000), b.addr(0x5002), 1);
			b.addRegisterReference(0, b.addr(0x4000), "r5");
			b.addStackReference(0, b.addr(0x4000), 0x20);
			b.addMemoryReference(0, b.addr(0x4001), b.range(0x5000, 0x5003));
			b.addMemoryReference(0, b.addr(0x4002), b.range(0x5000, 0x5003));
		}

		assertEquals(5, manager.getReferenceCountFrom(0, b.addr(0x4000)));
		assertEquals(3, manager.getReferenceCountTo(0, b.addr(0x5000)));
		assertEquals(0, manager.getReferenceCountFrom(0, b.addr(0x5000)));
		assertEquals(0, manager.getReferenceCountTo(0, b.addr(0x4000)));
	}

	@Test
	public void testSaveAndLoad() throws CancelledException, IOException, VersionException {
		try (Transaction tx = b.startTransaction()) {
			b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003));
			b.addOffsetReference(0, b.addr(0x4000), b.addr(0x5001), false, 20);
			b.addShiftedReference(0, b.addr(0x4000), b.addr(0x5002), 1);
		}

		File saved = b.save();

		try (@SuppressWarnings("hiding") // On purpose
		ToyDBTraceBuilder b = new ToyDBTraceBuilder(saved)) {
			@SuppressWarnings("hiding") // On purpose
			DBTraceReferenceManager manager = b.trace.getReferenceManager();

			Collection<? extends DBTraceReference> refs =
				manager.getReferencesFrom(0, b.addr(0x4000));
			assertEquals(3, refs.size());

			TraceReference ref;

			ref = manager.getReference(0, b.addr(0x4000), b.range(0x5000, 0x5003), -1);
			assertEquals(DBTraceReference.class, ref.getClass());
			assertEquals(RefType.DATA, ref.getReferenceType());
			assertEquals(SourceType.DEFAULT, ref.getSource());
			assertNull(ref.getAssociatedSymbol());

			ref = manager.getReference(0, b.addr(0x4000), b.addr(0x5001), -1);
			assertEquals(DBTraceOffsetReference.class, ref.getClass());
			assertEquals(20, ((DBTraceOffsetReference) ref).getOffset());

			ref = manager.getReference(0, b.addr(0x4000), b.addr(0x5002), -1);
			assertEquals(DBTraceShiftedReference.class, ref.getClass());
			assertEquals(1, ((DBTraceShiftedReference) ref).getShift());
		}
	}

	@Test
	public void testUndo() throws IOException {
		try (Transaction tx = b.startTransaction()) {
			b.addMemoryReference(0, b.addr(0x4000), b.range(0x5000, 0x5003));
			b.addOffsetReference(0, b.addr(0x4000), b.addr(0x5001), false, 20);
			b.addShiftedReference(0, b.addr(0x4000), b.addr(0x5002), 1);
		}

		assertEquals(3, manager.getReferenceCountFrom(0, b.addr(0x4000)));

		b.trace.undo();

		assertEquals(0, manager.getReferenceCountFrom(0, b.addr(0x4000)));

		b.trace.redo();

		assertEquals(3, manager.getReferenceCountFrom(0, b.addr(0x4000)));
	}

	@Test
	public void testOverlaySpaces() throws Exception {
		try (Transaction tx = b.startTransaction()) {
			AddressSpace os = b.trace.getMemoryManager()
					.createOverlayAddressSpace("test",
						b.trace.getBaseAddressFactory().getDefaultAddressSpace());

			b.addMemoryReference(0, os.getAddress(0x4000), b.range(os, 0x5000, 0x5003));
			b.addMemoryReference(0, os.getAddress(0x4001), b.range(0x5004, 0x5007));
			b.addMemoryReference(0, b.addr(0x4002), b.range(os, 0x5008, 0x500b));
		}

		File saved = b.save();

		try (@SuppressWarnings("hiding") // On purpose
		ToyDBTraceBuilder b = new ToyDBTraceBuilder(saved)) {
			@SuppressWarnings("hiding") // On purpose
			DBTraceReferenceManager manager = b.trace.getReferenceManager();

			AddressSpace ds = b.trace.getBaseAddressFactory().getDefaultAddressSpace();
			AddressSpace os = b.trace.getBaseAddressFactory().getAddressSpace("test");
			assertNotNull(os);

			TraceReference ref;

			ref = manager.getReference(0, os.getAddress(0x4000), b.range(os, 0x5000, 0x5003), -1);
			assertNotNull(ref);
			assertEquals(os, ref.getFromAddress().getAddressSpace());
			assertEquals(os, ref.getToAddress().getAddressSpace());

			ref = manager.getReference(0, os.getAddress(0x4001), b.range(0x5004, 0x5007), -1);
			assertNotNull(ref);
			assertEquals(os, ref.getFromAddress().getAddressSpace());
			assertEquals(ds, ref.getToAddress().getAddressSpace());

			ref = manager.getReference(0, b.addr(0x4002), b.range(os, 0x5008, 0x500b), -1);
			assertNotNull(ref);
			assertEquals(ds, ref.getFromAddress().getAddressSpace());
			assertEquals(os, ref.getToAddress().getAddressSpace());

			assertEquals(0, manager.getReferenceCountFrom(0, b.addr(0x4001)));
			assertEquals(1, manager.getReferenceCountFrom(0, os.getAddress(0x4001)));

			assertEquals(0, manager.getReferenceCountFrom(0, os.getAddress(0x4002)));
			assertEquals(1, manager.getReferenceCountFrom(0, b.addr(0x4002)));

			assertEquals(0, manager.getReferenceCountTo(0, os.getAddress(0x5004)));
			assertEquals(1, manager.getReferenceCountTo(0, b.addr(0x5004)));

			assertEquals(0, manager.getReferenceCountTo(0, b.addr(0x5008)));
			assertEquals(1, manager.getReferenceCountTo(0, os.getAddress(0x5008)));
		}
	}
}
