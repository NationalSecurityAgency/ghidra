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
package ghidra.program.database.symbol;

import static org.junit.Assert.*;

import java.util.Iterator;
import java.util.List;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class EquateManagerTest extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private AddressSpace space;
	private EquateTable equateTable;
	private int transactionID;

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram("Test", ProgramBuilder._TOY, this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		Memory memory = program.getMemory();
		transactionID = program.startTransaction("Test");
		memory.createInitializedBlock("test", addr(0), 5000, (byte) 0, TaskMonitor.DUMMY, false);

		equateTable = program.getEquateTable();

	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	@Test
	public void testCreateEquate() throws Exception {
		Equate equate = equateTable.createEquate("Test", 100);
		assertNotNull(equate);

		equate = equateTable.createEquate("Test-2", 101);
		assertNotNull(equate);
	}

	@Test
	public void testCreateEquateDuplicate() throws Exception {
		equateTable.createEquate("Test", 100);
		equateTable.createEquate("Test-2", 1000);
		try {
			equateTable.createEquate("Test", 10);
			Assert.fail("Should have gotten duplicate name exception");
		}
		catch (DuplicateNameException e) {
			// expected
		}
	}

	@Test
	public void testBadNameForCreate() throws Exception {
		try {
			equateTable.createEquate("", 100);
			Assert.fail("Should have gotten invalid input exception");
		}
		catch (InvalidInputException e) {
			// expected
		}
		try {
			equateTable.createEquate(null, 100);
			Assert.fail("Should have gotten invalid input exception");
		}
		catch (InvalidInputException e) {
			// expected
		}
	}

	@Test
	public void testBasicEquate() throws Exception {
		Equate equate = equateTable.createEquate("Test", 100);
		assertEquals("Test", equate.getName());

		assertEquals(100, equate.getValue());
	}

	@Test
	public void testAddReferenceOnEquate() throws Exception {
		Equate eqTest = equateTable.createEquate("Test", 100);
		eqTest.addReference(addr(100), 0);
		EquateReference[] refs = eqTest.getReferences();
		assertEquals(1, refs.length);

		eqTest.addReference(addr(200), 1);
		refs = eqTest.getReferences();
		assertEquals(2, refs.length);
		eqTest.addReference(addr(200), 2);

		//This test is now irrelevant because it checks to see that a newly
		//created equate on an operand will remove the old one.  That is
		//no longer the case.

		/*Equate eqTest2 = equateTable.createEquate("Test-2", 200);
		eqTest2.addReference(addr(200), 2);
		Equate equateFromTable = equateTable.getEquate(addr(200) , 2);
		assertTrue(!eqTest.equals(equateFromTable));*/
//		List equatesFromTable = equateTable.getEquates(addr(200), 2);
//		assertTrue(equatesFromTable.size() == 2);
//		assertTrue(eqTest.equals(equatesFromTable.get(0)));
//		assertTrue(eqTest2.equals(equatesFromTable.get(1)));
//		
//		Equate eqTest3 = equateTable.createEquate("Test-3", 100);
//		eqTest3.addReference(addr(100), 0);
//		refs = eqTest.getReferences();
//		assertEquals(3, refs.length);
//		assertEquals(1, eqTest3.getReferenceCount());
	}

	@Test
	public void testRemoveReference() throws Exception {
		Equate eq = equateTable.createEquate("Test", 1);

		eq.addReference(addr(10), 0);
		eq.addReference(addr(20), 1);
		eq.addReference(addr(20), 0);

		Equate temp = equateTable.getEquate(addr(10), 0, 1);
		assertNotNull(temp);
		temp = equateTable.getEquate(addr(20), 0, 1);
		assertEquals(temp, eq);

		eq.addReference(addr(30), 2);
		eq.addReference(addr(30), 1);
		eq.addReference(addr(30), 0);

		for (int i = 0; i < 3; i++) {
			Equate te = equateTable.getEquate(addr(30), i, 1);
			assertNotNull(te);
		}

		eq.addReference(addr(40), 3);
		eq.addReference(addr(40), 0);

		EquateReference[] refs = eq.getReferences();
		assertEquals(8, refs.length);

		// remove references
		eq.removeReference(addr(40), 3);
		assertNull(equateTable.getEquate(addr(40), 3, 1));
		refs = eq.getReferences();
		assertEquals(7, refs.length);
	}

	@Test
	public void testEquateIterator() throws Exception {

		for (int i = 10; i < 20; i++) {
			equateTable.createEquate("Test_" + i, i);
		}

		// get all equates
		int count = 0;
		Iterator<Equate> it = equateTable.getEquates();
		while (it.hasNext()) {
			it.next();
			++count;
		}
		assertEquals(10, count);

	}

	@Test
	public void testEquateAddressIterator() throws Exception {
		Equate eq = equateTable.createEquate("Test", 1);

		eq.addReference(addr(100), 3);
		eq.addReference(addr(50), 2);
		eq.addReference(addr(50), 0);
		eq.addReference(addr(10), 0);
		eq.addReference(addr(20), 1);

		eq = equateTable.createEquate("Test2", 200);
		eq.addReference(addr(1000), 0);
		eq.addReference(addr(1200), 0);
		eq.addReference(addr(1400), 0);
		eq.addReference(addr(1400), 1);

		AddressIterator iter = equateTable.getEquateAddresses();
		int count = 0;
		while (iter.hasNext()) {
			iter.next();
			++count;
		}
		assertEquals(7, count);// should filter out duplicate ref addrs
	}

	@Test
	public void testEquateAddressIteratorStart() throws Exception {
		Equate eq = equateTable.createEquate("Test", 1);

		eq.addReference(addr(100), 3);
		eq.addReference(addr(50), 2);
		eq.addReference(addr(50), 0);
		eq.addReference(addr(10), 0);
		eq.addReference(addr(20), 1);

		AddressIterator iter = equateTable.getEquateAddresses(addr(50));
		int count = 0;
		while (iter.hasNext()) {
			iter.next();
			++count;
		}
		assertEquals(2, count);// should filter out duplicate ref addrs
	}

	@Test
	public void testEquateAddressIteratorSet() throws Exception {
		Equate eq = equateTable.createEquate("Test", 1);

		eq.addReference(addr(100), 3);
		eq.addReference(addr(50), 2);
		eq.addReference(addr(500), 0);
		eq.addReference(addr(10), 0);
		eq.addReference(addr(20), 1);

		Equate eq2 = equateTable.createEquate("Test2", 500);
		eq2.addReference(addr(100), 0);
		eq2.addReference(addr(110), 0);

		AddressSet set = new AddressSet(addr(0), addr(20));
		set.addRange(addr(300), addr(500));

		AddressIterator iter = equateTable.getEquateAddresses(set);
		// should not get 100, 110		

		assertEquals(addr(10), iter.next());
		assertEquals(addr(20), iter.next());
		assertEquals(addr(500), iter.next());
		assertTrue(!iter.hasNext());
		assertNull(iter.next());

		set = new AddressSet(addr(0), addr(120));
		set.addRange(addr(200), addr(510));
		iter = equateTable.getEquateAddresses(set);
		// should get all addresses
		assertEquals(addr(10), iter.next());
		assertEquals(addr(20), iter.next());
		assertEquals(addr(50), iter.next());
		assertEquals(addr(100), iter.next());
		assertEquals(addr(110), iter.next());
		assertEquals(addr(500), iter.next());
		assertNull(iter.next());

	}

	@Test
	public void testGetEquatesByValue() throws Exception {
		// now create equates with the same value
		for (int i = 0; i < 10; i++) {
			equateTable.createEquate("EQ_0" + i, 500);
		}
		equateTable.createEquate("Test", 500);
		equateTable.createEquate("Test2", 500);
		List<Equate> equates = equateTable.getEquates(500);
		assertEquals(12, equates.size());
	}

	@Test
	public void testGetEquateByName() throws Exception {
		equateTable.createEquate("Test", 500);
		equateTable.createEquate("Test2", 1500);

		Equate eq1 = equateTable.getEquate("Test2");
		assertNotNull(eq1);
		assertEquals("Test2", eq1.getName());

		Equate eq2 = equateTable.getEquate("Test");
		assertNotNull(eq2);
		assertEquals("Test", eq2.getName());

		assertNull(equateTable.getEquate("foo"));
	}

	@Test
	public void testRemoveEquate() throws Exception {
		equateTable.createEquate("Test", 500);
		equateTable.createEquate("Test2", 1500);

		equateTable.removeEquate("Test");
		assertNull(equateTable.getEquate("Test"));
		assertNotNull(equateTable.getEquate("Test2"));
	}

	@Test
	public void testRemoveEquateWithRefs() throws Exception {
		Equate eq = equateTable.createEquate("Test", 1);

		eq.addReference(addr(100), 3);
		eq.addReference(addr(50), 2);
		eq.addReference(addr(500), 0);
		eq = equateTable.createEquate("Test2", 1500);
		eq.addReference(addr(300), 0);

		equateTable.removeEquate("Test");
		assertNull(equateTable.getEquate(addr(100), 3, 1));
		assertNull(equateTable.getEquate("Test"));
		assertNotNull(equateTable.getEquate("Test2"));

		eq.removeReference(addr(300), 0);
		assertNotNull(equateTable.getEquate("Test2"));
	}

	@Test
	public void testRemoveEquatesInRange() throws Exception {
		Equate eq = equateTable.createEquate("Test1", 100);
		equateTable.createEquate("Test2", 200);
		equateTable.createEquate("Test3", 200);
		Equate eq2 = equateTable.createEquate("Test4", 1500);
		equateTable.createEquate("Test5", 1500);
		equateTable.createEquate("Test6", 1500);

		eq.addReference(addr(100), 3);
		eq.addReference(addr(50), 2);
		eq.addReference(addr(500), 0);

		eq2.addReference(addr(10), 0);
		eq2.addReference(addr(100), 3);
		eq2.addReference(addr(2000), 2);

		int count = 0;
		Iterator<Equate> iter = equateTable.getEquates();
		while (iter.hasNext()) {
			iter.next();
			++count;

		}
		assertEquals(6, count);

		equateTable.deleteAddressRange(addr(50), addr(500), TaskMonitor.DUMMY);
		assertNull(equateTable.getEquate("Test1"));
		assertNotNull(equateTable.getEquate("Test4"));
		assertEquals(0, equateTable.getEquates(addr(100), 0).size());
		assertNotNull(equateTable.getEquate(addr(10), 0, 1500));
		assertNull(equateTable.getEquate(addr(10), 0, 100));

		count = 0;
		iter = equateTable.getEquates();
		while (iter.hasNext()) {
			iter.next();
			++count;
		}
		assertEquals(5, count);
	}

	@Test
	public void testRenameEquate() throws Exception {
		Equate eq = equateTable.createEquate("Test1", 100);
		equateTable.createEquate("Test2", 200);
		equateTable.createEquate("Test3", 200);
		Equate eq2 = equateTable.createEquate("Test4", 1500);

		eq.addReference(addr(100), 3);
		eq.addReference(addr(50), 2);
		eq.addReference(addr(500), 0);

		eq2.addReference(addr(10), 0);
		eq2.addReference(addr(100), 3);
		eq2.addReference(addr(2000), 2);

		eq.renameEquate("foo");
		assertEquals("foo", eq.getName());
		Equate temp = equateTable.getEquate("foo");
		assertEquals(eq, temp);
	}

	@Test
	public void testRenameEquateDuplicate() throws Exception {
		Equate eq = equateTable.createEquate("Test1", 100);
		equateTable.createEquate("Test2", 200);
		equateTable.createEquate("Test3", 200);
		equateTable.createEquate("Test4", 1500);

		try {
			eq.renameEquate("Test3");
			Assert.fail("Should have gotten DuplicateNameException");
		}
		catch (DuplicateNameException e) {
			// expected
		}
		eq = equateTable.createEquate("foo", 100);
		eq.renameEquate("foo");// nothing should happen
		try {
			eq.renameEquate("Test4");
			Assert.fail("Should have gotten DuplicateNameException");
		}
		catch (DuplicateNameException e) {
			// expected
		}
	}

	@Test
	public void testRenameEquateBadName() throws Exception {
		Equate eq = equateTable.createEquate("Test1", 100);
		try {
			eq.renameEquate("");
			Assert.fail("Empty string should be invalid!");
		}
		catch (InvalidInputException e) {
			// expected
		}
		try {
			eq.renameEquate(null);
			Assert.fail("Empty string should be invalid!");
		}
		catch (InvalidInputException e) {
			// expected
		}
	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

}
