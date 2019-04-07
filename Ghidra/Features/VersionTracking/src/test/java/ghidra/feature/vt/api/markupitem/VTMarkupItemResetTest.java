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
package ghidra.feature.vt.api.markupitem;

import static ghidra.feature.vt.db.VTTestUtils.createProgramCorrelator;
import static ghidra.feature.vt.db.VTTestUtils.createRandomMarkupItemStub;
import static org.junit.Assert.assertEquals;

import java.util.Collection;

import org.junit.*;

import ghidra.feature.vt.api.db.AssociationDatabaseManager;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.feature.vt.db.VTBaseTestCase;
import ghidra.feature.vt.db.VTTestUtils;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class VTMarkupItemResetTest extends VTBaseTestCase {

	private int testTransactionID;
	private AssociationDatabaseManager associationDBM;

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		associationDBM = db.getAssociationManagerDBM();
		testTransactionID = db.startTransaction("Test Match Set Setup");
	}

	@Override
	@After
	public void tearDown() throws Exception {
		db.endTransaction(testTransactionID, false);
		db.release(VTTestUtils.class);
	}

	@Test
	public void testDBMarkupItemStorageReset_ClearDestinationAddress() {
		//
		// Test that the markup item storage is removed (reset) from the DB when the
		// destination address is cleared *and not other user-defined values are set*.
		//
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		VTMatch match = matchSet.addMatch(createRandomMatch(db));
		VTMarkupItem markupItem = createRandomMarkupItemStub(match);
		VTAssociation association = match.getAssociation();
		Address destinationAddress = addr();
		VTMarkupItem unappliedMarkupItem = markupItem;

		unappliedMarkupItem.setDestinationAddress(destinationAddress);

		Collection<VTMarkupItem> markupItems = getStoredMarkupItems(association);
		assertEquals(1, markupItems.size());

		unappliedMarkupItem.setDestinationAddress(null);
		markupItems = getStoredMarkupItems(association);
		assertEquals(0, markupItems.size());
	}

	@Test
	public void testDBMarkupItemStorageReset_ClearConsidered() {
		//
		// Test that the markup item storage is removed (reset) from the DB when the
		// user's considered state is cleared *and not other user-defined values are set*.
		//
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		VTMatch match = matchSet.addMatch(createRandomMatch(db));
		VTMarkupItem markupItem = createRandomMarkupItemStub(match);
		VTAssociation association = match.getAssociation();
		VTMarkupItem unappliedMarkupItem = markupItem;

		unappliedMarkupItem.setConsidered(VTMarkupItemConsideredStatus.IGNORE_DONT_CARE);

		Collection<VTMarkupItem> markupItems = getStoredMarkupItems(association);
		assertEquals(1, markupItems.size());

		unappliedMarkupItem.setConsidered(VTMarkupItemConsideredStatus.UNCONSIDERED);
		markupItems = getStoredMarkupItems(association);
		assertEquals(0, markupItems.size());
	}

	@Test
	public void testDBMarkupItemStorageReset_Unapply() {
		//
		// Test that the markup item storage is removed (reset) from the DB when the
		// markup item is unapplied *and not other user-defined values are set*.
		//
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		VTMatch match = matchSet.addMatch(createRandomMatch(db));
		VTMarkupItem markupItem = createRandomMarkupItemStub(match);
		VTAssociation association = match.getAssociation();
		Address destinationAddress = addr();
		VTMarkupItem unappliedMarkupItem = markupItem;

		unappliedMarkupItem.setDefaultDestinationAddress(destinationAddress, "Test Source");

		try {
			association.setAccepted();
			unappliedMarkupItem.apply(createRandomApplyAction(unappliedMarkupItem), null);
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception applying a test markup item");
		}
		catch (VTAssociationStatusException e) {
			Assert.fail("Unexpected exception accepting an association");
		}

		Collection<VTMarkupItem> markupItems = getStoredMarkupItems(association);
		assertEquals(1, markupItems.size());

		try {
			unappliedMarkupItem.unapply();
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception unapplying a test markup item");
		}

		markupItems = getStoredMarkupItems(association);
		assertEquals(0, markupItems.size());
	}

	@Test
	public void testDBMarkupItemStorageResetDoesntHappen_Unapply() {
		//
		// Test that the markup item storage is only not removed when the destination address
		// is set by the user.
		//
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		VTMatch match = matchSet.addMatch(createRandomMatch(db));
		VTMarkupItem markupItem = createRandomMarkupItemStub(match);
		VTAssociation association = match.getAssociation();
		Address destinationAddress = addr();
		VTMarkupItem unappliedMarkupItem = markupItem;

		// 1) Set an address - this will prevent a reset
		unappliedMarkupItem.setDestinationAddress(destinationAddress);

		try {
			unappliedMarkupItem.apply(createRandomApplyAction(unappliedMarkupItem), null);
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception applying a test markup item");
		}

		Collection<VTMarkupItem> markupItems = getStoredMarkupItems(association);
		assertEquals(1, markupItems.size());

		try {
			unappliedMarkupItem.unapply();
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception unapplying a test markup item");
		}

		markupItems = getStoredMarkupItems(association);
		assertEquals("DB item was removed even though we have a user address value that we " +
			"want to stay in the DB", 1, markupItems.size());
	}

	@Test
	public void testDBMarkupItemStorageResetDoesntHappen_ClearConsidered() {
		//
		// Test that the markup item storage is not removed the considered status is cleared, but
		// the the destination address is set by the user.
		//
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		VTMatch match = matchSet.addMatch(createRandomMatch(db));
		VTMarkupItem markupItem = createRandomMarkupItemStub(match);
		VTAssociation association = match.getAssociation();
		Address destinationAddress = addr();
		VTMarkupItem unappliedMarkupItem = markupItem;

		// 1) Set an address - this will prevent a reset
		unappliedMarkupItem.setDestinationAddress(destinationAddress);

		unappliedMarkupItem.setConsidered(VTMarkupItemConsideredStatus.IGNORE_DONT_KNOW);

		Collection<VTMarkupItem> markupItems = getStoredMarkupItems(association);
		assertEquals(1, markupItems.size());

		unappliedMarkupItem.setConsidered(VTMarkupItemConsideredStatus.UNCONSIDERED);

		markupItems = getStoredMarkupItems(association);
		assertEquals("DB item was removed even though we have a user address value that we " +
			"want to stay in the DB", 1, markupItems.size());
	}

	@Test
	public void testDBMarkupItemStorageResetDoesntHappen_ClearDestinationAddress() {
		//
		// Test that the markup item storage is not removed when the destination address is 
		// cleared, but the considered status was set.
		//
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		VTMatch match = matchSet.addMatch(createRandomMatch(db));
		VTMarkupItem markupItem = createRandomMarkupItemStub(match);
		VTAssociation association = match.getAssociation();
		Address destinationAddress = addr();
		VTMarkupItem unappliedMarkupItem = markupItem;

		// 1) Set a considered status - this will prevent a reset
		unappliedMarkupItem.setConsidered(VTMarkupItemConsideredStatus.IGNORE_DONT_KNOW);

		unappliedMarkupItem.setDestinationAddress(destinationAddress);

		Collection<VTMarkupItem> markupItems = getStoredMarkupItems(association);
		assertEquals(1, markupItems.size());

		unappliedMarkupItem.setDestinationAddress(null);

		markupItems = getStoredMarkupItems(association);
		assertEquals("DB item was removed even though we have a user address value that we " +
			"want to stay in the DB", 1, markupItems.size());
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	@SuppressWarnings("unchecked")
	private Collection<VTMarkupItem> getStoredMarkupItems(VTAssociation association) {
		Object markupItemManager = getInstanceField("markupManager", association);
		return (Collection<VTMarkupItem>) invokeInstanceMethod("getStoredMarkupItems",
			markupItemManager, new Class[] { TaskMonitor.class },
			new Object[] { TaskMonitorAdapter.DUMMY_MONITOR });
	}

	private VTMarkupItemApplyActionType createRandomApplyAction(VTMarkupItem item) {
		VTMarkupItemApplyActionType action = VTMarkupItemApplyActionType.values()[getRandomInt(1,
			VTMarkupItemApplyActionType.values().length - 1)];
		while (!item.supportsApplyAction(action)) {
			action = VTMarkupItemApplyActionType.values()[getRandomInt(1,
				VTMarkupItemApplyActionType.values().length - 1)];
		}
		return action;
	}
}
