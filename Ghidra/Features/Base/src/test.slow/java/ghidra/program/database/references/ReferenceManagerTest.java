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
package ghidra.program.database.references;

import static org.junit.Assert.*;

import java.util.Iterator;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test the reference manager for the database implementation.
 * 
 * 
 */
public class ReferenceManagerTest extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private AddressSpace space;
	private ReferenceDBManager refMgr;
	private Listing listing;
	private int transactionID;

	/**
	 * Constructor
	 * @param arg0
	 */
	public ReferenceManagerTest() {
		super();
	}

	/* 
	 * @see TestCase#setUp()
	 */
    @Before
    public void setUp() throws Exception {
		program = createDefaultProgram("Test", ProgramBuilder._TOY, this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		refMgr = (ReferenceDBManager) program.getReferenceManager();
		listing = program.getListing();
		transactionID = program.startTransaction("Test");
		program.getMemory().createInitializedBlock("code", addr(0), 10000, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);
	}

    @After
    public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	private static String[] getPathAsArray(String... strings) {
		return strings;
	}

@Test
    public void testAddMemReference() throws Exception {
		Reference ref =
			refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED,
				2);
		refMgr.setPrimary(ref, false);

		ref = refMgr.getReference(addr(512), addr(256), 2);
		assertNotNull(ref);
		assertTrue(!ref.isPrimary());
		assertTrue(ref.getSource() == SourceType.USER_DEFINED);
		assertTrue(ref.isOperandReference());

		ref =
			refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED,
				-1);
		refMgr.setPrimary(ref, false);
		ref = refMgr.getReference(addr(784), addr(256), -1);
		assertTrue(ref.isMnemonicReference());
		assertTrue(!ref.isPrimary());
		assertTrue(!ref.isOperandReference());
		assertTrue(ref.getSource() == SourceType.USER_DEFINED);

		refMgr.addMemoryReference(addr(600), addr(256), RefType.UNCONDITIONAL_CALL,
			SourceType.USER_DEFINED, 2);
		ref = refMgr.getReference(addr(600), addr(256), 2);
		assertNotNull(ref);
		refMgr.setPrimary(ref, false);
		assertEquals(SymbolUtilities.SUB_LEVEL, refMgr.getReferenceLevel(addr(256)));
	}

@Test
    public void testAddMemReferenceUndoRedo() throws Exception {
		Reference ref =
			refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED,
				2);
		refMgr.setPrimary(ref, false);
		program.endTransaction(transactionID, true);

		transactionID = program.startTransaction("Test");
		ref =
			refMgr.addMemoryReference(addr(512), addr(700), RefType.FLOW, SourceType.USER_DEFINED,
				-1);
		refMgr.setPrimary(ref, false);
		program.endTransaction(transactionID, true);

		program.undo();

		// get the reference to 700 -- should be gone
		ref = refMgr.getReference(addr(512), addr(700), 2);

		assertNull(ref);

		program.redo();
		ref = refMgr.getReference(addr(512), addr(700), -1);
		assertNotNull(ref);

		transactionID = program.startTransaction("Test");
	}

@Test
    public void testSetPrimaryReference() throws Exception {
		Reference ref =
			refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED,
				2);
		refMgr.setPrimary(ref, false);
		ref = refMgr.getReference(addr(512), addr(256), 2);
		assertTrue(!ref.isPrimary());
		refMgr.setPrimary(ref, true);
		assertNotNull(refMgr.getPrimaryReferenceFrom(addr(512), 2));

		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);
		refMgr.setPrimary(ref, false);
		ref = refMgr.getReference(addr(784), addr(256), -1);
	}

@Test
    public void testHasMemRefsFrom() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(1024), addr(100), RefType.FLOW, SourceType.USER_DEFINED, 1);

		assertTrue(!refMgr.hasReferencesFrom(addr(256)));
		assertTrue(!refMgr.hasReferencesFrom(addr(510)));
		assertTrue(refMgr.hasReferencesFrom(addr(512)));
		assertTrue(refMgr.hasReferencesFrom(addr(1024)));

		assertTrue(!refMgr.hasReferencesFrom(addr(512), -1));
		assertTrue(!refMgr.hasReferencesFrom(addr(512), 0));
		assertTrue(!refMgr.hasReferencesFrom(addr(512), 1));
		assertTrue(refMgr.hasReferencesFrom(addr(512), 2));

		assertTrue(!refMgr.hasReferencesFrom(addr(1024), -1));
		assertTrue(refMgr.hasReferencesFrom(addr(1024), 0));
		assertTrue(refMgr.hasReferencesFrom(addr(1024), 1));
		assertTrue(!refMgr.hasReferencesFrom(addr(1024), 2));
	}

@Test
    public void testHasMemRefsTo() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(1024), addr(100), RefType.FLOW, SourceType.USER_DEFINED, 1);

		assertTrue(refMgr.hasReferencesTo(addr(100)));
		assertTrue(refMgr.hasReferencesTo(addr(256)));
		assertTrue(!refMgr.hasReferencesTo(addr(0)));
		assertTrue(!refMgr.hasReferencesTo(addr(512)));
		assertTrue(!refMgr.hasReferencesTo(addr(1024)));
	}

//	public void testFallthroughIterator() throws Exception {
//		refMgr.addMemReference(addr(100), addr(256),RefType.FALL_THROUGH, true, 2, false);
//		refMgr.addMemReference(addr(110), addr(256),RefType.FALL_THROUGH, true, 2, false);
//		refMgr.addMemReference(addr(120), addr(256),RefType.FALL_THROUGH, true, 2, false);
//		refMgr.addMemReference(addr(130), addr(256),RefType.FALL_THROUGH, true, 2, false);
//
//		// add refs that are not fallthroughs
//		refMgr.addMemReference(addr(103), addr(256),RefType.FLOW, true, 2, false);
//		refMgr.addMemReference(addr(105), addr(256),RefType.COMPUTED_JUMP, true, 0, false);
//		refMgr.addMemReference(addr(118), addr(256),RefType.TERMINATOR, true, 1, false);
//		refMgr.addMemReference(addr(125), addr(256),RefType.TERMINATOR, true, 1, false);
//		refMgr.addMemReference(addr(135), addr(256),RefType.COMPUTED_JUMP, true, 1, false);
//	
//		AddressIterator iter = refMgr.getFallthroughRefIterator(addr(100));
//		assertNotNull(iter);
//		assertTrue(iter.hasNext());
//		assertEquals(addr(100), iter.next());	
//		
//		assertTrue(iter.hasNext());
//		assertEquals(addr(110), iter.next());	
//
//		assertTrue(iter.hasNext());
//		assertEquals(addr(120), iter.next());	
//
//		assertTrue(iter.hasNext());
//		assertEquals(addr(130), iter.next());
//		assertTrue(!iter.hasNext());	
//	}

@Test
    public void testHasFlows() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(1024), addr(100), RefType.FLOW, SourceType.USER_DEFINED, 1);

		refMgr.addMemoryReference(addr(300), addr(256), RefType.COMPUTED_JUMP,
			SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(320), addr(500), RefType.DATA, SourceType.USER_DEFINED, 1);

		assertTrue(refMgr.hasFlowReferencesFrom(addr(512)));
		assertTrue(refMgr.hasFlowReferencesFrom(addr(1024)));

		assertTrue(refMgr.hasFlowReferencesFrom(addr(300)));
		assertTrue(!refMgr.hasFlowReferencesFrom(addr(320)));

	}

@Test
    public void testFlowCount() {
		assertTrue(!refMgr.hasFlowReferencesFrom(addr(100)));
		refMgr.addMemoryReference(addr(100), addr(500), RefType.COMPUTED_JUMP,
			SourceType.USER_DEFINED, 0);

		assertTrue(refMgr.hasFlowReferencesFrom(addr(100)));

		refMgr.removeReference(addr(100), addr(500), 0);
		assertTrue(!refMgr.hasFlowReferencesFrom(addr(100)));

		refMgr.removeReference(addr(100), addr(500), 0);
		assertTrue(!refMgr.hasFlowReferencesFrom(addr(100)));

	}

@Test
    public void testMultipleFlowCount() {
		assertTrue(!refMgr.hasFlowReferencesFrom(addr(100)));
		refMgr.addMemoryReference(addr(100), addr(500), RefType.COMPUTED_JUMP,
			SourceType.USER_DEFINED, 0);
		assertTrue(refMgr.hasFlowReferencesFrom(addr(100)));
		refMgr.addMemoryReference(addr(100), addr(600), RefType.COMPUTED_JUMP,
			SourceType.USER_DEFINED, 0);
		assertTrue(refMgr.hasFlowReferencesFrom(addr(100)));
		refMgr.addMemoryReference(addr(100), addr(700), RefType.COMPUTED_JUMP,
			SourceType.USER_DEFINED, 0);
		assertTrue(refMgr.hasFlowReferencesFrom(addr(100)));

		refMgr.removeReference(addr(100), addr(500), 0);
		assertTrue(refMgr.hasFlowReferencesFrom(addr(100)));

		refMgr.removeReference(addr(100), addr(600), 0);
		assertTrue(refMgr.hasFlowReferencesFrom(addr(100)));

		refMgr.removeReference(addr(100), addr(700), 0);
		assertTrue(!refMgr.hasFlowReferencesFrom(addr(100)));

	}

@Test
    public void testFlowCountNonRefType() {
		assertTrue(!refMgr.hasFlowReferencesFrom(addr(100)));
		refMgr.addMemoryReference(addr(100), addr(500), RefType.READ_WRITE,
			SourceType.USER_DEFINED, 0);

		assertTrue(!refMgr.hasFlowReferencesFrom(addr(100)));

		refMgr.removeReference(addr(100), addr(500), 0);
		assertTrue(!refMgr.hasFlowReferencesFrom(addr(100)));
	}

@Test
    public void testClearPrimaryReference() throws Exception {
		Reference ref =
			refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED,
				2);
		refMgr.setPrimary(ref, false);
		ref = refMgr.getReference(addr(512), addr(256), 2);
		assertTrue(!ref.isPrimary());
		refMgr.setPrimary(ref, true);
		ref = refMgr.getReference(addr(512), addr(256), 2);
		assertTrue(ref.isPrimary());

		refMgr.setPrimary(ref, false);
		assertNull(refMgr.getPrimaryReferenceFrom(addr(512), 2));

	}

@Test
    public void testGetMemReferencesFrom() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(1024), addr(100), RefType.FLOW, SourceType.USER_DEFINED, 1);

		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);

		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		// this one should not get added again
		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);

		Reference[] refs = refMgr.getReferencesFrom(addr(784));
		assertEquals(2, refs.length);

		refs = refMgr.getReferencesFrom(addr(1024));
		assertEquals(3, refs.length);

		refs = refMgr.getReferencesFrom(addr(256));
		assertEquals(0, refs.length);

		assertEquals(2, refMgr.getReferenceCountFrom(addr(784)));
		assertEquals(3, refMgr.getReferenceCountFrom(addr(1024)));

	}

@Test
    public void testGetMemRefsIterator() throws Exception {

		refMgr.addMemoryReference(addr(112), addr(50), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(200), addr(300), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(1024), addr(100), RefType.FLOW, SourceType.USER_DEFINED, 1);

		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);
		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);

		ReferenceIterator iter = refMgr.getReferencesTo(addr(256));
		assertNotNull(iter);
		assertTrue(iter.hasNext());
		Reference ref = iter.next();
		assertNotNull(ref);
		assertEquals(addr(512), ref.getFromAddress());

		ref = iter.next();
		assertNotNull(ref);
		assertEquals(addr(1024), ref.getFromAddress());
		assertEquals(0, ref.getOperandIndex());

		ref = iter.next();
		assertNotNull(ref);
		assertEquals(addr(1024), ref.getFromAddress());
		assertEquals(1, ref.getOperandIndex());

		ref = iter.next();
		assertNotNull(ref);
		assertEquals(addr(784), ref.getFromAddress());
		assertEquals(-1, ref.getOperandIndex());

		ref = iter.next();
		assertNotNull(ref);
		assertEquals(addr(784), ref.getFromAddress());
		assertEquals(2, ref.getOperandIndex());

		assertTrue(!iter.hasNext());
		assertNull(iter.next());

		iter = refMgr.getReferencesTo(addr(100));
		ref = iter.next();
		assertNotNull(ref);
		assertEquals(addr(1024), ref.getFromAddress());
		assertEquals(1, ref.getOperandIndex());

		assertTrue(!iter.hasNext());
		assertNull(iter.next());

	}

@Test
    public void testRemoveMemReference() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(512), addr(1024), RefType.FLOW, SourceType.USER_DEFINED, 1);
		Reference ref = refMgr.getReference(addr(512), addr(256), 2);
		refMgr.delete(ref);
		ref = refMgr.getReference(addr(512), addr(256), 2);
		assertNull(ref);
	}

@Test
    public void testRemoveMemRefByAddress() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(512), addr(1024), RefType.FLOW, SourceType.USER_DEFINED, 1);
		Reference ref = refMgr.getReference(addr(512), addr(256), 2);
		assertNotNull(ref);
		refMgr.removeReference(addr(512), addr(256), 2);
		ref = refMgr.getReference(addr(512), addr(256), 2);
		assertNull(ref);
		ref = refMgr.getReference(addr(512), addr(1024), 1);
		assertNotNull(ref);
	}

@Test
    public void testRemoveMemRefBadIndex() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(512), addr(1024), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.removeReference(addr(512), addr(256), 1);
		Reference ref = refMgr.getReference(addr(512), addr(256), 2);
		assertNotNull(ref);
	}

@Test
    public void testGetMemRefsFrom() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);

		assertEquals(2, refMgr.getReferencesFrom(addr(1024)).length);
	}

@Test
    public void testGetMemReferenceIterator() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(784), addr(256), RefType.FLOW, SourceType.USER_DEFINED, -1);

		ReferenceIterator it = refMgr.getReferenceIterator(addr(600));
		assertEquals(addr(784), it.next().getFromAddress());
		assertEquals(addr(1024), it.next().getFromAddress());
		assertEquals(addr(1024), it.next().getFromAddress());
		assertNull(it.next());

		it = refMgr.getReferenceIterator(addr(1024));
		assertEquals(addr(1024), it.next().getFromAddress());
		assertEquals(addr(1024), it.next().getFromAddress());
		assertNull(it.next());
	}

@Test
    public void testSetAssociation() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		Reference ref = refMgr.getReference(addr(512), addr(256), 2);
		Symbol s =
			program.getSymbolTable().createLabel(addr(256), "fred", SourceType.USER_DEFINED);
		refMgr.setAssociation(s, ref);
		ref = refMgr.getReference(addr(512), addr(256), 2);
		assertEquals(s.getID(), ref.getSymbolID());
	}

@Test
    public void testFromIterator() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(1024), addr(100), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(100), addr(200), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(110), addr(300), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(600), addr(400), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(300), addr(500), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(700), addr(600), RefType.FLOW, SourceType.USER_DEFINED, 1);

		AddressIterator iter = refMgr.getReferenceSourceIterator(addr(0), true);
		assertNotNull(iter);

		assertTrue(iter.hasNext());
		assertEquals(addr(100), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(110), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(300), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(512), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(600), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(700), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(1024), iter.next());

		assertTrue(!iter.hasNext());

		iter = refMgr.getReferenceSourceIterator(addr(500), true);
		Address addr = iter.next();
		assertEquals(addr(512), addr);

		addr = iter.next();
		assertEquals(addr(600), addr);

		addr = iter.next();
		assertEquals(addr(700), addr);

		addr = iter.next();
		assertEquals(addr(1024), addr);
		assertTrue(!iter.hasNext());

		iter = refMgr.getReferenceSourceIterator(addr(1000), true);
		assertTrue(iter.hasNext());
		assertNotNull(iter.next());
		assertTrue(!iter.hasNext());
	}

@Test
    public void testFromIteratorSet() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(1024), addr(100), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(100), addr(200), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(110), addr(300), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(600), addr(400), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(300), addr(500), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(700), addr(600), RefType.FLOW, SourceType.USER_DEFINED, 1);

		AddressSet set = new AddressSet(addr(0), addr(110));
		set.addRange(addr(300), addr(700));
		set.addRange(addr(1000), addr(2000));

		AddressIterator iter = refMgr.getReferenceSourceIterator(set, true);
		assertNotNull(iter);
		assertTrue(iter.hasNext());
		assertEquals(addr(100), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(110), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(300), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(512), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(600), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(700), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(1024), iter.next());

		assertTrue(!iter.hasNext());

	}

@Test
    public void testToIteratorSet() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(1024), addr(100), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(100), addr(200), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(110), addr(300), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(600), addr(400), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(300), addr(500), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(700), addr(600), RefType.FLOW, SourceType.USER_DEFINED, 1);

		AddressSet set = new AddressSet(addr(0), addr(110));
		set.addRange(addr(200), addr(400));
		set.addRange(addr(450), addr(2000));
		AddressIterator iter = refMgr.getReferenceDestinationIterator(set, true);
		assertTrue(iter.hasNext());
		assertEquals(addr(100), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(200), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(256), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(300), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(400), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(500), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(600), iter.next());

		assertTrue(!iter.hasNext());

	}

@Test
    public void testToIterator() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(1024), addr(100), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(100), addr(200), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(110), addr(300), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(600), addr(400), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(300), addr(500), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(700), addr(600), RefType.FLOW, SourceType.USER_DEFINED, 1);

		AddressIterator iter = refMgr.getReferenceDestinationIterator(addr(100), true);

		assertTrue(iter.hasNext());
		assertEquals(addr(100), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(200), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(256), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(300), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(400), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(500), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(600), iter.next());

		assertTrue(!iter.hasNext());
	}

	// Test interating refs over addressSpace with imagebase non zero
@Test
    public void testToIterator2() throws Exception {
		program.setImageBase(addr(80), true);
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(1024), addr(100), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(100), addr(200), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(110), addr(300), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(600), addr(400), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(300), addr(500), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(700), addr(600), RefType.FLOW, SourceType.USER_DEFINED, 1);

		AddressIterator iter =
			refMgr.getReferenceDestinationIterator(program.getAddressFactory().getAddressSet(),
				true);

		assertTrue(iter.hasNext());
		assertEquals(addr(100), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(200), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(256), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(300), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(400), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(500), iter.next());

		assertTrue(iter.hasNext());
		assertEquals(addr(600), iter.next());

		assertTrue(!iter.hasNext());
	}

@Test
    public void testRemoveMemRefsInRange() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(1024), addr(100), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(100), addr(200), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(110), addr(300), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(600), addr(400), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(300), addr(500), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(700), addr(600), RefType.FLOW, SourceType.USER_DEFINED, 1);

		refMgr.removeAllReferencesFrom(addr(100), addr(2000));
		assertEquals(0, refMgr.getReferencesFrom(addr(1024)).length);
		assertNull(refMgr.getReference(addr(100), addr(200), 1));

	}

@Test
    public void testRemoveMemRefsNotInRange() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 0);
		refMgr.addMemoryReference(addr(1024), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(1024), addr(100), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(100), addr(200), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(110), addr(300), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(600), addr(400), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(300), addr(500), RefType.FLOW, SourceType.USER_DEFINED, 1);
		refMgr.addMemoryReference(addr(700), addr(600), RefType.FLOW, SourceType.USER_DEFINED, 1);

		refMgr.removeAllReferencesFrom(addr(2000), addr(3000));
		assertEquals(3, refMgr.getReferencesFrom(addr(1024)).length);
	}

@Test
    public void testUpdateRefType() throws Exception {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED, 2);
		Reference ref = refMgr.getReference(addr(512), addr(256), 2);
		assertEquals(RefType.FLOW, ref.getReferenceType());

		refMgr.updateRefType(ref, RefType.DATA);
		ref = refMgr.getReference(addr(512), addr(256), 2);
		assertEquals(RefType.DATA, ref.getReferenceType());
	}

@Test
    public void testRefLevelAfterUpdate() {
		refMgr.addMemoryReference(addr(512), addr(256), RefType.DATA, SourceType.USER_DEFINED, 2);
		Reference ref = refMgr.getReference(addr(512), addr(256), 2);
		assertEquals(RefType.DATA, ref.getReferenceType());
		Symbol[] symbols = program.getSymbolTable().getSymbols(addr(256));
		assertEquals("DAT_00000100", symbols[0].getName());

		refMgr.updateRefType(ref, RefType.FLOW);
		ref = refMgr.getReference(addr(512), addr(256), 2);
		assertEquals(RefType.FLOW, ref.getReferenceType());
		symbols = program.getSymbolTable().getSymbols(addr(256));
		assertEquals("LAB_00000100", symbols[0].getName());

		refMgr.updateRefType(ref, RefType.DATA);
		ref = refMgr.getReference(addr(512), addr(256), 2);
		assertEquals(RefType.DATA, ref.getReferenceType());
		symbols = program.getSymbolTable().getSymbols(addr(256));
		assertEquals("DAT_00000100", symbols[0].getName());

	}

@Test
    public void testAddOffsetReference() {
		refMgr.addOffsetMemReference(addr(100), addr(600), 100, RefType.COMPUTED_JUMP,
			SourceType.USER_DEFINED, 0);

		Reference ref = refMgr.getReference(addr(100), addr(600), 0);
		assertNotNull(ref);

		assertEquals(addr(100), ref.getFromAddress());
		assertEquals(addr(600), ref.getToAddress());
		assertEquals(0, ref.getOperandIndex());
		assertEquals(true, ref.getSource() == SourceType.USER_DEFINED);

		OffsetReference off = (OffsetReference) ref;
		assertEquals(addr(500), off.getBaseAddress());
		assertEquals(100, off.getOffset());

		refMgr.addMemoryReference(addr(100), addr(1000), RefType.COMPUTED_JUMP,
			SourceType.USER_DEFINED, 0);

		Reference[] refs = refMgr.getReferences(addr(100), 0);
		assertEquals(2, refs.length);

		refMgr.addMemoryReference(addr(100), addr(1005), RefType.COMPUTED_JUMP,
			SourceType.USER_DEFINED, -1);
		refs = refMgr.getReferences(addr(100), 0);
		assertEquals(2, refs.length);

		refs = refMgr.getReferencesFrom(addr(100));
		assertEquals(3, refs.length);

		ReferenceIterator iter = refMgr.getReferencesTo(addr(600));
		assertTrue(iter.hasNext());
		assertNotNull(iter.next());
		assertTrue(!iter.hasNext());

		refMgr.removeAllReferencesFrom(addr(100));
		refs = refMgr.getReferences(addr(100), 0);
		assertEquals(0, refs.length);

		iter = refMgr.getReferencesTo(addr(100));
		assertTrue(!iter.hasNext());
		assertNull(iter.next());

		iter = refMgr.getReferencesTo(addr(500));
		assertTrue(!iter.hasNext());
		assertNull(iter.next());
		refMgr.delete(ref);
	}

	// Test External References
@Test
    public void testAddExternalReference() throws Exception {

		refMgr.addExternalReference(addr(100), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);

		CodeUnit cu = listing.getCodeUnitAt(addr(100));
		Reference ref = cu.getExternalReference(0);
		assertNotNull(ref);
		ExternalLocation extLoc = ((ExternalReference) ref).getExternalLocation();
		assertEquals("io.dll", extLoc.getLibraryName());
		assertEquals(addr(100), ref.getFromAddress());
		assertEquals("label", extLoc.getLabel());
		assertEquals(0, ref.getOperandIndex());
		assertEquals(true, ref.getSource() == SourceType.USER_DEFINED);

		refMgr.addExternalReference(addr(100), "foo.dll", "ABC", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		ref = cu.getExternalReference(0);
		assertNotNull(ref);
		extLoc = ((ExternalReference) ref).getExternalLocation();
		assertEquals("foo.dll", extLoc.getLibraryName());

		refMgr.addExternalReference(addr(500), "foo.dll", null, addr(4000),
			SourceType.USER_DEFINED, 0, RefType.DATA);
		cu = listing.getCodeUnitAt(addr(500));
		ref = cu.getExternalReference(0);

	}

@Test
    public void testGetExternalReferences() throws Exception {
		refMgr.addExternalReference(addr(100), "foo.dll", "ABC", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(100), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(100), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(500), "login.dll", "ABC", null, SourceType.USER_DEFINED,
			0, RefType.DATA);

		Reference[] refs = refMgr.getReferencesFrom(addr(100));
		assertEquals(1, refs.length);

		refMgr.addExternalReference(addr(100), "one", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);

		refMgr.addExternalReference(addr(100), "two", "aa", null, SourceType.USER_DEFINED, 1,
			RefType.DATA);

		refs = refMgr.getReferencesFrom(addr(100));
		assertEquals(2, refs.length);

	}

@Test
    public void testIteratorExternalReferences() throws Exception {
		refMgr.addExternalReference(addr(100), "foo.dll", "ABC", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(100), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(100), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(200), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(500), "login.dll", null, addr(4000),
			SourceType.USER_DEFINED, 0, RefType.DATA);

		AddressIterator iter = refMgr.getReferenceSourceIterator(addr(100), true);
		Address a = iter.next();
		assertNotNull(a);
		assertEquals(addr(100), a);

		a = iter.next();
		assertNotNull(a);
		assertEquals(addr(200), a);

		a = iter.next();
		assertNotNull(a);
		assertEquals(addr(500), a);

		assertTrue(!iter.hasNext());
	}

@Test
    public void testIteratorSetExternaleReferences() throws Exception {
		refMgr.addExternalReference(addr(100), "foo.dll", "label", null, SourceType.USER_DEFINED,
			0, RefType.DATA);
		refMgr.addExternalReference(addr(100), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(100), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(200), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(500), "login.dll", "label", null, SourceType.USER_DEFINED,
			0, RefType.DATA);

		refMgr.addExternalReference(addr(600), "login.dll", "label", null, SourceType.USER_DEFINED,
			0, RefType.DATA);
		AddressSet set = new AddressSet();
		set.addRange(addr(100), addr(100));
		set.addRange(addr(150), addr(210));

		AddressIterator iter = refMgr.getReferenceSourceIterator(set, true);

		Address a = iter.next();
		assertNotNull(a);
		assertEquals(addr(100), a);

		a = iter.next();
		assertNotNull(a);
		assertEquals(addr(200), a);

		assertNull(iter.next());
	}

@Test
    public void testExternalReferencesIterator() throws Exception {
		Reference ref =
			refMgr.addExternalReference(addr(100), "foo.dll", "ABC", null, SourceType.USER_DEFINED,
				0, RefType.DATA);
		refMgr.addExternalReference(addr(200), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(300), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(400), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		refMgr.addExternalReference(addr(500), "login.dll", null, addr(4000),
			SourceType.USER_DEFINED, 0, RefType.DATA);

		ReferenceIterator it = refMgr.getExternalReferences();
		assertTrue(it.hasNext());
		ref = it.next();
		assertTrue(ref instanceof ExternalReference);
		assertEquals("ABC", ((ExternalReference) ref).getLabel());
		assertNotNull(it.next());
		assertNotNull(it.next());
		assertNotNull(it.next());
		assertNotNull(it.next());
		assertTrue(!it.hasNext());
	}

@Test
    public void testRemoveExternalReferences() throws Exception {

		refMgr.addExternalReference(addr(100), "foo.dll", "ABC", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);
		CodeUnit cu = listing.getCodeUnitAt(addr(100));
		Reference ref = cu.getExternalReference(0);
		assertNotNull(ref);
		Reference[] refs = refMgr.getReferencesFrom(addr(100));
		assertEquals(1, refs.length);

		refMgr.delete(ref);

		assertNull(cu.getExternalReference(0));
		refs = refMgr.getReferencesFrom(addr(100));
		assertEquals(0, refs.length);
	}

@Test
    public void testRemoveAllExtRefsInRange() throws Exception {
		refMgr.addExternalReference(addr(100), "io.dll", "label", null, SourceType.USER_DEFINED, 0,
			RefType.DATA);

		refMgr.addExternalReference(addr(100), "io.dll", "label1", null, SourceType.USER_DEFINED,
			0, RefType.DATA);
		refMgr.addExternalReference(addr(110), "io.dll", "label2", null, SourceType.USER_DEFINED,
			0, RefType.DATA);
		refMgr.addExternalReference(addr(120), "io.dll", "label3", null, SourceType.USER_DEFINED,
			0, RefType.DATA);
		refMgr.addExternalReference(addr(130), "io.dll", "label4", null, SourceType.USER_DEFINED,
			0, RefType.DATA);

		refMgr.addExternalReference(addr(1000), "io.dll", "label5", null, SourceType.USER_DEFINED,
			0, RefType.DATA);

		refMgr.removeAllReferencesFrom(addr(0), addr(500));

		CodeUnit cu = listing.getCodeUnitAt(addr(100));
		assertNull(cu.getExternalReference(0));

		cu = listing.getCodeUnitAt(addr(110));
		assertNull(cu.getExternalReference(0));

		cu = listing.getCodeUnitAt(addr(120));
		assertNull(cu.getExternalReference(0));

		cu = listing.getCodeUnitAt(addr(130));
		assertNull(cu.getExternalReference(0));

		cu = listing.getCodeUnitAt(addr(1000));
		assertNotNull(cu.getExternalReference(0));
	}

@Test
    public void testAddReference() throws Exception {
		Reference ref1 =
			refMgr.addMemoryReference(addr(512), addr(256), RefType.FLOW, SourceType.USER_DEFINED,
				2);
		assertTrue(ref1.isPrimary());

		refMgr.setPrimary(ref1, false);

		Reference ref = refMgr.getReference(addr(512), addr(256), 2);
		assertNotNull(ref);
		assertEquals(addr(512), ref.getFromAddress());
		assertEquals(addr(256), ref.getToAddress());
		assertEquals(RefType.FLOW, ref.getReferenceType());
		assertTrue(ref.isMemoryReference());
		assertTrue(ref.getSource() == SourceType.USER_DEFINED);
		assertTrue(!ref.isPrimary());

		Reference ref2 =
			refMgr.addMemoryReference(addr(512), addr(256), RefType.READ, SourceType.USER_DEFINED,
				2);

		ref = refMgr.getReference(addr(512), addr(256), 2);
		assertEquals(ref2, ref);
		assertNotNull(ref);
		assertEquals(addr(512), ref.getFromAddress());
		assertEquals(addr(256), ref.getToAddress());
		assertEquals(RefType.READ, ref.getReferenceType());
		assertTrue(ref.isMemoryReference());
		assertTrue(ref.getSource() == SourceType.USER_DEFINED);
		assertTrue(ref.isPrimary());

		Reference ref3 =
			refMgr.addMemoryReference(addr(512), addr(256), RefType.WRITE, SourceType.USER_DEFINED,
				2);

		ref = refMgr.getReference(addr(512), addr(256), 2);
		assertEquals(ref3, ref); // ref type differs
		assertNotNull(ref);
		assertEquals(addr(512), ref.getFromAddress());
		assertEquals(addr(256), ref.getToAddress());
		assertEquals(RefType.READ_WRITE, ref.getReferenceType());
		assertTrue(ref.isMemoryReference());
		assertTrue(ref.getSource() == SourceType.USER_DEFINED);
		assertTrue(ref.isPrimary());
	}

@Test
    public void testAddManyReferencesTo() throws Exception {
		Reference ref = null;
		int cnt = 2 * RefList.BIG_REFLIST_THRESHOLD;
		for (int i = 0; i < cnt; i++) {
			ref =
				refMgr.addMemoryReference(addr(512 + i), addr(256), RefType.FLOW,
					SourceType.USER_DEFINED, 2);
		}
		assertEquals(cnt, refMgr.getReferenceCountTo(addr(256)));

		int index = 0;
		ReferenceIterator referencesTo = refMgr.getReferencesTo(addr(256));
		while (referencesTo.hasNext()) {
			ref = referencesTo.next();
			assertEquals(addr(512 + index), ref.getFromAddress());
			++index;
		}
		assertEquals(cnt, index);

		assertEquals(SymbolUtilities.LAB_LEVEL, refMgr.getReferenceLevel(addr(256)));
		ref = refMgr.updateRefType(ref, RefType.UNCONDITIONAL_CALL);
		assertEquals(SymbolUtilities.SUB_LEVEL, refMgr.getReferenceLevel(addr(256)));

		program.endTransaction(transactionID, true);
		transactionID = program.startTransaction("Test");

		ref = refMgr.updateRefType(ref, RefType.FLOW);
		assertEquals(SymbolUtilities.LAB_LEVEL, refMgr.getReferenceLevel(addr(256)));

		// cause invalidation of cache
		program.endTransaction(transactionID, true);
		program.undo();
		transactionID = program.startTransaction("Test");

		index = 0;
		referencesTo = refMgr.getReferencesTo(addr(256));
		while (referencesTo.hasNext()) {
			ref = referencesTo.next();
			assertEquals(addr(512 + index), ref.getFromAddress());
			++index;
		}
		assertEquals(cnt, index);
		assertEquals(SymbolUtilities.SUB_LEVEL, refMgr.getReferenceLevel(addr(256)));

		Iterator<Reference> refs = refMgr.getReferencesTo(addr(256));
		while (refs.hasNext()) {
			ref = refs.next();
			refMgr.delete(ref);
		}
		assertEquals(0, refMgr.getReferenceCountTo(addr(256)));
	}

//	private void doAdd(int thresholdCnt, PrintWriter pw) throws Exception {
//		transactionID = program.startTransaction("Test");
//		
//		RefList.BIG_REFLIST_THRESHOLD = thresholdCnt;
//		
//		System.gc(); System.gc();
//		
//		long start = System.nanoTime();
//		
//		for (int i = 0; i < 50000; i++) {
//			refMgr.addMemoryReference(addr(512+i), addr(256),RefType.FLOW, SourceType.USER_DEFINED, 2);
//		}
//
//		long delta = (System.nanoTime() - start) / 1000000;
//		
//		if (pw != null) {
//			pw.println(thresholdCnt + ", " + delta);
//		}
//		
//		System.out.println("threshold=" + thresholdCnt + " time(ms)=" + delta);
//		
//		program.endTransaction(transactionID, true);
//		program.undo();
//	}
//	
//	public void testBigRefList() throws Exception {
//		
//		PrintWriter pw = new PrintWriter("C:\\Documents and Settings\\mysid\\Desktop\\test.dat");
//		
//		program.endTransaction(transactionID, true);
//		
//		// wait for things to settle down
//		for (int i = 1000; i < 1500; i+=100) {
//			doAdd(i, null);
//		}
//		
//		for (int n = 0; n < 5; n++) {
//			for (int i = 1000; i < 5000; i+=100) {
//				doAdd(i, pw);
//			}
//		}
//		
//		pw.close();
//		
//		transactionID = program.startTransaction("Test");
//	}

@Test
    public void testAddExternalEntryPoint() throws Exception {
		refMgr.addExternalEntryPointRef(addr(0x200));
		ReferenceIterator ri = refMgr.getReferencesTo(addr(0x200));
		assertTrue(ri.hasNext());
		assertTrue(ri.next().isEntryPointReference());
		assertTrue(!ri.hasNext());
		Symbol s = program.getSymbolTable().getSymbols(addr(0x200))[0];
		assertEquals("EXT_00000200", s.getName());
		assertTrue(s.getSource() == SourceType.DEFAULT);
		assertTrue(s.isExternalEntryPoint());
	}

@Test
    public void testRemoveExternalEntryPoint() throws Exception {
		refMgr.addExternalEntryPointRef(addr(0x200));
		Symbol[] s = program.getSymbolTable().getSymbols(addr(0x200));
		assertEquals(1, s.length);
		refMgr.removeExternalEntryPoint(addr(0x200));
		s = program.getSymbolTable().getSymbols(addr(0x200));
		assertEquals(0, s.length);
	}

@Test
    public void testExtEntryIterator() throws Exception {
		Address[] addrs =
			new Address[] { addr(0x200), addr(0x300), addr(0x400), addr(0x500), addr(0x600),
				addr(0x700), addr(0x800), addr(0x900) };
		for (int i = 0; i < addrs.length; i++) {
			refMgr.addExternalEntryPointRef(addrs[i]);
		}

		AddressIterator iter = refMgr.getExternalEntryIterator();
		for (int i = 0; i < addrs.length; i++) {
			assertTrue(iter.hasNext());
			Address addr = iter.next();
			assertEquals(addrs[i], addr);
			ReferenceIterator ri = refMgr.getReferencesTo(addr);
			assertTrue(ri.hasNext());
			assertTrue(ri.next().isEntryPointReference());
			assertTrue(!ri.hasNext());
		}
		assertTrue(!iter.hasNext());

	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

}
