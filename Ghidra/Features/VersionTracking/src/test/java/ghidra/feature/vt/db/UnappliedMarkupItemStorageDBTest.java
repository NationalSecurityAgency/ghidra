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
package ghidra.feature.vt.db;

import static ghidra.feature.vt.db.VTTestUtils.createProgramCorrelator;
import static ghidra.feature.vt.db.VTTestUtils.createRandomMarkupItemStub;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Collection;

import org.junit.*;

import ghidra.feature.vt.api.db.MarkupItemStorageDB;
import ghidra.feature.vt.api.db.VTAssociationDB;
import ghidra.feature.vt.api.impl.MarkupItemStorage;
import ghidra.feature.vt.api.impl.MarkupItemStorageImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markupitem.MarkupTypeTestStub;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class UnappliedMarkupItemStorageDBTest extends VTBaseTestCase {

	private int testTransactionID;

	public UnappliedMarkupItemStorageDBTest() {
		super();
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		System.err.println(System.getProperty("java.class.path"));
		testTransactionID = db.startTransaction("Test Match Set Setup");

	}

	@Override
	@After
	public void tearDown() throws Exception {
		db.endTransaction(testTransactionID, false);
		db.release(VTTestUtils.class);

	}

	@Test
	public void testSetDestinationAddress() {
		VTMatch match = createMatchSetWithOneMatch();
		VTAssociationDB association = (VTAssociationDB) match.getAssociation();

		MarkupItemStorageImpl storageImpl =
			new MarkupItemStorageImpl(association, MarkupTypeTestStub.INSTANCE, addr(100));

		// 
		// Setting the address with anything other than a user-defined address should not 
		// create a storage object
		//
		String addressSource = "Test Source";
		Address destinationAddress = addr();
		MarkupItemStorage newStorage =
			storageImpl.setDestinationAddress(destinationAddress, addressSource);
		assertTrue("A database entry was created for a non-user-defined address",
			(newStorage instanceof MarkupItemStorageImpl));

		addressSource = VTMarkupItem.USER_DEFINED_ADDRESS_SOURCE;
		newStorage = storageImpl.setDestinationAddress(destinationAddress, addressSource);
		assertTrue("A database entry was not created for a user-defined address",
			(newStorage instanceof MarkupItemStorageDB));
	}

	@Test
	public void testSetDestinationAddressToNull() {
		VTMatch match = createMatchSetWithOneMatch();
		VTAssociationDB association = (VTAssociationDB) match.getAssociation();

		MarkupItemStorageImpl storageImpl =
			new MarkupItemStorageImpl(association, MarkupTypeTestStub.INSTANCE, addr(100));

		// 
		// Setting the address with anything other than a user-defined address should not 
		// create a storage object
		//
		String addressSource = "Test Source";

		MarkupItemStorage newStorage = storageImpl.setDestinationAddress(null, addressSource);
		assertTrue("A database entry was created for a non-user-defined, null address",
			(newStorage instanceof MarkupItemStorageImpl));

		Address destinationAddress = addr();
		addressSource = VTMarkupItem.USER_DEFINED_ADDRESS_SOURCE;
		newStorage = storageImpl.setDestinationAddress(destinationAddress, addressSource);
		assertTrue("A database entry was not created for a user-defined address",
			(newStorage instanceof MarkupItemStorageDB));

		// call the DB version with null to make sure it doesn't fail
		newStorage.setDestinationAddress(null, addressSource);
	}

	@Test
	public void testSetConsidered() {
		VTMatch match = createMatchSetWithOneMatch();
		VTAssociationDB association = (VTAssociationDB) match.getAssociation();

		MarkupItemStorageImpl storageImpl =
			new MarkupItemStorageImpl(association, MarkupTypeTestStub.INSTANCE, addr(100));

		//
		// Test that setting ignored to true creates a DB storage
		//         
		MarkupItemStorage newStorage = storageImpl.setStatus(VTMarkupItemStatus.DONT_CARE);
		assertTrue("A database entry was not created when setting the storage to ignored",
			(newStorage instanceof MarkupItemStorageDB));

		newStorage = newStorage.reset();
		assertEquals(VTMarkupItemStatus.UNAPPLIED, newStorage.getStatus());
		assertTrue("We should have impl storage object when reseting the status",
			(newStorage instanceof MarkupItemStorageImpl));

		//
		// Test that any set destination address is retained when setting ignored to true and false
		// 

		storageImpl =
			new MarkupItemStorageImpl(association, MarkupTypeTestStub.INSTANCE, addr(200));

		// A) For a non-user-defined address
		String addressSource = "Test Source";
		Address destinationAddress = addr();
		newStorage = storageImpl.setDestinationAddress(destinationAddress, addressSource);
		assertTrue("A database entry was created for a non-user-defined address",
			(newStorage instanceof MarkupItemStorageImpl));

		newStorage = storageImpl.setStatus(VTMarkupItemStatus.DONT_CARE);
		assertEquals(VTMarkupItemStatus.DONT_CARE, newStorage.getStatus());
		assertTrue("A database entry was not created when setting the storage to ignored",
			(newStorage instanceof MarkupItemStorageDB));
		assertEquals("The destination address was lost after setting the storage to ignored",
			destinationAddress, newStorage.getDestinationAddress());

		// B) For a user-defined address
		storageImpl =
			new MarkupItemStorageImpl(association, MarkupTypeTestStub.INSTANCE, addr(300));

		addressSource = VTMarkupItem.USER_DEFINED_ADDRESS_SOURCE;
		destinationAddress = addr();
		newStorage = storageImpl.setDestinationAddress(destinationAddress, addressSource);
		assertTrue("A database entry was not created for a user-defined address",
			(newStorage instanceof MarkupItemStorageDB));

		newStorage = newStorage.setStatus(VTMarkupItemStatus.DONT_CARE);
		assertTrue("A database entry was not created when setting the storage to ignored",
			(newStorage instanceof MarkupItemStorageDB));
		assertEquals("The destination address was lost after setting the storage to ignored",
			destinationAddress, newStorage.getDestinationAddress());

	}

	@Test
	public void testSetApplyFailed() {
		VTMatch match = createMatchSetWithOneMatch();
		VTAssociationDB association = (VTAssociationDB) match.getAssociation();

		MarkupItemStorageImpl storageImpl =
			new MarkupItemStorageImpl(association, MarkupTypeTestStub.INSTANCE, addr(100));

		//
		// Test that setting apply failed to true creates a DB storage
		//
		MarkupItemStorage newStorage = storageImpl.setApplyFailed(getRandomString());
		assertTrue("A database entry was not created when setting the storage to 'apply failed'",
			(newStorage instanceof MarkupItemStorageDB));

		//
		// Test that any set destination address is retained when setting apply failed to true and false
		// 
		storageImpl =
			new MarkupItemStorageImpl(association, MarkupTypeTestStub.INSTANCE, addr(200));

		// A) For a non-user-defined address
		String addressSource = "Test Source";
		Address destinationAddress = addr();
		newStorage = storageImpl.setDestinationAddress(destinationAddress, addressSource);
		assertTrue("A database entry was created for a non-user-defined address",
			(newStorage instanceof MarkupItemStorageImpl));

		assertEquals(VTMarkupItemStatus.UNAPPLIED, newStorage.getStatus());

		newStorage = newStorage.setApplyFailed(getRandomString());
		assertEquals(VTMarkupItemStatus.FAILED_APPLY, newStorage.getStatus());
		assertTrue("A database entry was not created when setting the storage to 'apply failed'",
			(newStorage instanceof MarkupItemStorageDB));
		assertEquals("The destination address was lost after setting the storage to 'apply failed'",
			destinationAddress, newStorage.getDestinationAddress());

		// B) For a user-defined address
		storageImpl =
			new MarkupItemStorageImpl(association, MarkupTypeTestStub.INSTANCE, addr(300));
		addressSource = VTMarkupItem.USER_DEFINED_ADDRESS_SOURCE;
		destinationAddress = addr();
		newStorage = storageImpl.setDestinationAddress(destinationAddress, addressSource);
		assertTrue("A database entry was not created for a user-defined address",
			(newStorage instanceof MarkupItemStorageDB));

		newStorage = newStorage.setApplyFailed(getRandomString());
		assertTrue("A database entry was not created when setting the storage to 'apply failed'",
			(newStorage instanceof MarkupItemStorageDB));
		assertEquals("The destination address was lost after setting the storage to 'apply failed'",
			destinationAddress, newStorage.getDestinationAddress());
	}

	@Test
	public void testLoadingUnappliedMarkupItemFindsExistingStorageRecord()
			throws CancelledException {
		// 
		// Test that if we create a DB object, that a new 'equivalent' markup item will find and
		// use the matching DB record.
		//              
		VTMatch match = createMatchSetWithOneMatch();

		VTMarkupItem markupItem = createRandomMarkupItemStub(match);
		Address destinationAddress = addr();

		// trigger storage
		VTMarkupItem unappliedMarkupItem = markupItem;
		unappliedMarkupItem.setDestinationAddress(destinationAddress);

		VTAssociationDB association = (VTAssociationDB) match.getAssociation();
		Collection<VTMarkupItem> markupItems =
			association.getMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(1, markupItems.size());
		VTMarkupItem foundItem = markupItems.iterator().next();
		Object storage = getInstanceField("markupItemStorage", foundItem);

		assertTrue("The newly created unapplied markup item did not find the storage record" +
			"in the database", (storage instanceof MarkupItemStorageDB));
	}

	@Test
	public void testLoadingUnappliedMarkupItemWithNoExistingStorageRecord()
			throws CancelledException {
		// 
		// Test that if we create a DB object, that a new 'equivalent' markup item will find and
		// use the matching DB record.
		//              
		VTMatch match = createMatchSetWithOneMatch();

		VTMarkupItem markupItem = createRandomMarkupItemStub(match);
		VTAssociationDB association = (VTAssociationDB) match.getAssociation();
		Collection<VTMarkupItem> markupItems =
			association.getMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(1, markupItems.size());
		VTMarkupItem foundItem = markupItems.iterator().next();
		Object storage = getInstanceField("markupItemStorage", foundItem);
		assertTrue("The newly created unapplied markup item found a record in storage ",
			(storage instanceof MarkupItemStorageImpl));
	}

	private VTMatch createMatchSetWithOneMatch() {
		VTMatchInfo matchInfo = createRandomMatch(db);
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));
		return matchSet.addMatch(matchInfo);
	}

}
