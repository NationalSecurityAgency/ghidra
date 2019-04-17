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

import static ghidra.feature.vt.db.VTTestUtils.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Collection;
import java.util.Collections;

import org.junit.*;

import ghidra.feature.vt.api.db.MarkupItemStorageDB;
import ghidra.feature.vt.api.db.VTAssociationDB;
import ghidra.feature.vt.api.impl.MarkupItemManagerImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.feature.vt.api.util.VersionTrackingApplyException;
import ghidra.program.model.address.Address;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import mockit.Mocked;
import mockit.Verifications;

public class VTAssociationDBTest extends VTBaseTestCase {

	private int testTransactionID;

	public VTAssociationDBTest() {
		super();
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		testTransactionID = db.startTransaction("Test Match Set Setup");
	}

	@Override
	@After
	public void tearDown() throws Exception {
		db.endTransaction(testTransactionID, false);
		db.release(VTTestUtils.class);

	}

	@Test
	public void testAddAndGetAndRemoveMarkupItem() throws Exception {

		VTMatch match = createMatchSetWithOneMatch();

		VTMarkupItem markupItem = createRandomMarkupItemStub(match);
		VTAssociation association = match.getAssociation();
		VTMarkupItemApplyActionType applyAction = createRandomApplyAction(markupItem);
		VTMarkupItemStatus markupStatus = applyAction.getApplyStatus();

		Address destinationAddress = addr();

		VTMarkupItem unappliedMarkupItem = markupItem;
		unappliedMarkupItem.setDestinationAddress(destinationAddress);
		try {

			unappliedMarkupItem.apply(applyAction, null);
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception applying markup item");
		}

		Collection<VTMarkupItem> markupItems = getStoredMarkupItems(association);

		assertEquals(1, markupItems.size());
		VTMarkupItem markupItemFromDB = markupItems.iterator().next();

		assertTrue("Markup Item put into DB is not the same as the one we got back",
			areMarkupItemsEquivalent(markupItem, markupItemFromDB));
		assertEquals(destinationAddress, markupItemFromDB.getDestinationAddress());
		assertEquals(markupStatus, markupItemFromDB.getStatus());

		//
		// now test remove
		// 

		// just doing an unapply will not remove the DB, since we have put in a custom, 
		// USER_DEFINED address above...
		markupItemFromDB.unapply();
		markupItems = getStoredMarkupItems(association);
		assertEquals(1, markupItems.size());

		// ...now that we have unapplied, check that clearing the address will trigger a 
		// DB removal
		markupItem.setDestinationAddress(null);
		markupItems = getStoredMarkupItems(association);
		assertEquals(0, markupItems.size());
	}

	private boolean areMarkupItemsEquivalent(VTMarkupItem markupItem,
			VTMarkupItem markupItemFromDB) {
		Address sourceAddress1 = markupItem.getSourceAddress();
		Address sourceAddress2 = markupItemFromDB.getSourceAddress();
		if (!sourceAddress1.equals(sourceAddress2)) {
			return false;
		}

		return markupItem.getMarkupType() == markupItemFromDB.getMarkupType();
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

	private VTMarkupItemApplyActionType createRandomSuccessfulApplyAction(VTMarkupItem item) {
		VTMarkupItemApplyActionType action = createRandomApplyAction(item);
		while (!action.getApplyStatus().isUnappliable()) {
			action = createRandomApplyAction(item);
		}
		return action;
	}

	@SuppressWarnings("unchecked")
	private Collection<VTMarkupItem> getStoredMarkupItems(VTAssociation association) {
		Object markupItemManager = getInstanceField("markupManager", association);
		return (Collection<VTMarkupItem>) invokeInstanceMethod("getStoredMarkupItems",
			markupItemManager, new Class[] { TaskMonitor.class },
			new Object[] { TaskMonitorAdapter.DUMMY_MONITOR });
	}

	@Test
	public void testAssociationLocking() {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		//
		// To create our locking scenario we will create associations that are related and 
		// unrelated.  This allows us to test that competing associations will get locked-out
		// when any related associations are applied.  Also, unrelated associations should not
		// be locked-out.
		//

		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatchInfo relatedMatchInfo = createRandomMatchWithSameAssociation(mainMatchInfo);
		VTMatchInfo unrelatedMatchInfo = createRandomMatchWithUnrelatedAssociation(mainMatchInfo);
		VTMatchInfo conflictMatchInfoOnSource1 =
			createRandomMatchWithConflictingSourceAssociation(mainMatchInfo);
		VTMatchInfo conflictMatchInfoOnDestination2 =
			createRandomMatchWithConflictingDestinationAssociation(mainMatchInfo);

		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTMatch relatedMatch = addMatch(matchSet, relatedMatchInfo);
		VTMatch unrelatedMatch = addMatch(matchSet, unrelatedMatchInfo);
		VTMatch conflictMatchOnSource1 = addMatch(matchSet, conflictMatchInfoOnSource1);
		VTMatch conflictMatchOnDestination2 = addMatch(matchSet, conflictMatchInfoOnDestination2);

		VTMarkupItem mainMarkupItem = createRandomMarkupItemStub(mainMatch);
		VTAssociation mainAssociation = mainMatch.getAssociation();

		VTAssociation relatedAssociation = relatedMatch.getAssociation();
		VTAssociation unrelatedAssociation = unrelatedMatch.getAssociation();

		VTMarkupItem conflict1MarkupItem = createRandomMarkupItemStub(conflictMatchOnSource1);
		VTAssociation conflict1Association = conflictMatchOnSource1.getAssociation();
		VTAssociation conflict2Association = conflictMatchOnDestination2.getAssociation();

		//
		// test no locked associations when no committed markup items
		// 
		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());
		assertEquals(VTAssociationStatus.AVAILABLE, relatedAssociation.getStatus());
		assertEquals(VTAssociationStatus.AVAILABLE, unrelatedAssociation.getStatus());
		assertEquals(VTAssociationStatus.AVAILABLE, conflict1Association.getStatus());
		assertEquals(VTAssociationStatus.AVAILABLE, conflict2Association.getStatus());

		Address destinationAddress = addr();

		// 
		// commit an item and make sure the association is locked and competing associations are
		// locked-out
		// 
		mainMarkupItem.setDestinationAddress(destinationAddress);
		try {

			mainMarkupItem.apply(VTMarkupItemApplyActionType.REPLACE, null);
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected association status");// shouldn't happen
		}
		assertEquals(VTAssociationStatus.ACCEPTED, mainAssociation.getStatus());
		assertEquals(VTAssociationStatus.ACCEPTED, relatedAssociation.getStatus());
		assertEquals(VTAssociationStatus.AVAILABLE, unrelatedAssociation.getStatus());
		assertEquals(VTAssociationStatus.BLOCKED, conflict1Association.getStatus());
		assertEquals(VTAssociationStatus.BLOCKED, conflict2Association.getStatus());

		// 
		// verify we cannot commit from a competing association (others are locked-out)
		// 
		VTMarkupItem unappliedConflictItem = conflict1MarkupItem;
		try {
			unappliedConflictItem.setDestinationAddress(destinationAddress);
			unappliedConflictItem.apply(VTMarkupItemApplyActionType.REPLACE, null);
			Assert.fail("A competing association was not locked-out as expected");
		}
		catch (Exception e) {
			// good!
		}

		//
		// Unapply markup item and verify that its association is still accepted and that the
		// conflicting associations are still blocked
		//
		try {
			mainMarkupItem.unapply();
		}
		catch (VersionTrackingApplyException e1) {
			Assert.fail("Unexpected exception unapplying markup item");// shouldn't happen
		}
		assertEquals(VTAssociationStatus.ACCEPTED, mainAssociation.getStatus());
		assertEquals(VTAssociationStatus.ACCEPTED, relatedAssociation.getStatus());
		assertEquals(VTAssociationStatus.AVAILABLE, unrelatedAssociation.getStatus());
		assertEquals(VTAssociationStatus.BLOCKED, conflict1Association.getStatus());
		assertEquals(VTAssociationStatus.BLOCKED, conflict2Association.getStatus());
	}

	@Test
	public void testAddNewCompetingAssociationIsLockedOut() throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		//
		// To create our locking scenario we will create associations that are competing.  First
		// we will create and 'accept' an association.  Then we will create a competing association
		// and make sure that it is locked-out
		//

		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTMarkupItem mainMarkupItem = createRandomMarkupItemStub(mainMatch);
		VTAssociation mainAssociation = mainMatch.getAssociation();

		Address destinationAddress = addr();

		VTMarkupItem unappliedMarkupItem = mainMarkupItem;
		unappliedMarkupItem.setDestinationAddress(destinationAddress);
		try {
			unappliedMarkupItem.apply(VTMarkupItemApplyActionType.REPLACE, null);
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception applying markup item");// shouldn't happen
		}

		assertEquals(VTAssociationStatus.ACCEPTED, mainAssociation.getStatus());

		//
		// The competition
		//
		VTMatchInfo competingMatchInfo =
			createRandomMatchWithConflictingSourceAssociation(mainMatchInfo);
		VTMatch competingMatch = addMatch(matchSet, competingMatchInfo);
		VTAssociation competingAssociation = competingMatch.getAssociation();
		assertEquals(VTAssociationStatus.BLOCKED, competingAssociation.getStatus());
	}

	@Test
	public void testAddNewRelatedAssociationIsAccepted() throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		//
		// To create our locking scenario we will create associations that are related.  First
		// we will create and 'accept' an association.  Then we will create a competing association
		// and make sure that it is locked-out
		//

		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTMarkupItem mainMarkupItem = createRandomMarkupItemStub(mainMatch);
		VTAssociation mainAssociation = mainMatch.getAssociation();
		Address destinationAddress = addr();

		VTMarkupItem unappliedMarkupItem = mainMarkupItem;
		unappliedMarkupItem.setDestinationAddress(destinationAddress);
		try {
			unappliedMarkupItem.apply(VTMarkupItemApplyActionType.REPLACE, null);
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception applying markup item");// shouldn't happen
		}

		assertEquals(VTAssociationStatus.ACCEPTED, mainAssociation.getStatus());

		//
		// The competition
		//
		VTMatchInfo relatedMatchInfo = createRandomMatchWithSameAssociation(mainMatchInfo);
		VTMatch relatedMatch = addMatch(matchSet, relatedMatchInfo);
		VTAssociation competingAssociation = relatedMatch.getAssociation();
		assertTrue(mainAssociation == competingAssociation);
	}

	@Test
	public void testGetRelatedAssociations() {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		//
		// Exercise the lookup routines for finding related matches
		//

		VTMatchInfo mainMatchInfo = createRandomMatch(db);

		VTSession session = matchSet.getSession();
		VTAssociationManager associationManager = session.getAssociationManager();

		Address sourceAddress = mainMatchInfo.getSourceAddress();
		Collection<VTAssociation> relatedBySource =
			associationManager.getRelatedAssociationsBySourceAddress(sourceAddress);
		assertEquals(0, relatedBySource.size());

		Address destinationAddress = mainMatchInfo.getDestinationAddress();
		Collection<VTAssociation> relatedByDestination =
			associationManager.getRelatedAssociationsByDestinationAddress(destinationAddress);
		assertEquals(0, relatedByDestination.size());

		// just to exercise the code, even though it is logically covered by the above two calls
		Collection<VTAssociation> relatedBySourceAndDestination =
			associationManager.getRelatedAssociationsBySourceAndDestinationAddress(sourceAddress,
				destinationAddress);
		assertEquals(0, relatedBySourceAndDestination.size());

		VTMatchInfo relatedMatchInfo = createRandomMatchWithSameAssociation(mainMatchInfo);
		VTMatchInfo unrelatedMatchInfo = createRandomMatchWithUnrelatedAssociation(mainMatchInfo);
		VTMatchInfo conflictMatchInfoOnSource1 =
			createRandomMatchWithConflictingSourceAssociation(mainMatchInfo);
		VTMatchInfo conflictMatchInfoOnDestination2 =
			createRandomMatchWithConflictingDestinationAssociation(mainMatchInfo);

		addMatch(matchSet, mainMatchInfo);
		addMatch(matchSet, relatedMatchInfo);
		addMatch(matchSet, unrelatedMatchInfo);
		addMatch(matchSet, conflictMatchInfoOnSource1);
		addMatch(matchSet, conflictMatchInfoOnDestination2);

		// we expect two matches: 1 for the related match and one for the source conflict match
		relatedBySource = associationManager.getRelatedAssociationsBySourceAddress(sourceAddress);
		assertEquals(2, relatedBySource.size());

		// we expect two matches: 1 for the related match and one for the destination conflict match
		relatedByDestination =
			associationManager.getRelatedAssociationsByDestinationAddress(destinationAddress);
		assertEquals(2, relatedByDestination.size());

		// we expect three matches: 1 for the related match, one for the source conflict match and
		// one for the destination conflict match
		relatedBySourceAndDestination =
			associationManager.getRelatedAssociationsBySourceAndDestinationAddress(sourceAddress,
				destinationAddress);
		assertEquals(3, relatedBySourceAndDestination.size());
	}

	@Test
	public void testSetAcceptedFailsWhenNotAccepted() throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		//
		// To create our locking scenario we will create associations that are related.  First
		// we will create and 'accept' an association.  Then we will create a competing association
		// and make sure that we cannot make it accepted
		//

		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTMarkupItem mainMarkupItem = createRandomMarkupItemStub(mainMatch);
		VTAssociation mainAssociation = mainMatch.getAssociation();
		Address destinationAddress = addr();

		VTMarkupItem unappliedMarkupItem = mainMarkupItem;
		unappliedMarkupItem.setDestinationAddress(destinationAddress);
		try {
			unappliedMarkupItem.apply(VTMarkupItemApplyActionType.REPLACE, null);
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception applying markup item");// shouldn't happen
		}

		assertEquals(VTAssociationStatus.ACCEPTED, mainAssociation.getStatus());

		//
		// The competition
		//
		VTMatchInfo competingMatchInfo =
			createRandomMatchWithConflictingSourceAssociation(mainMatchInfo);
		VTMatch competingMatch = addMatch(matchSet, competingMatchInfo);
		VTAssociation competingAssociation = competingMatch.getAssociation();
		assertEquals(VTAssociationStatus.BLOCKED, competingAssociation.getStatus());

		try {
			competingAssociation.setAccepted();
			Assert.fail(
				"We were incorrectly allowed to 'accept' an association that is locked-out");
		}
		catch (VTAssociationStatusException ase) {
			// good!
		}
	}

	@Test
	public void testSetAssocaiationAccepted_WithNoCompetingAssociations() throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		//
		// The accepted association
		//
		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTAssociation mainAssociation = mainMatch.getAssociation();
		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());

		mainAssociation.setAccepted();
		assertEquals(VTAssociationStatus.ACCEPTED, mainAssociation.getStatus());
	}

	@Test
	public void testSetAssocaiationAccepted_WithCompetingAssociations() throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		//
		// The accepted association
		//
		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTAssociation mainAssociation = mainMatch.getAssociation();

		//
		// The competition
		//
		VTMatchInfo competingMatchInfo =
			createRandomMatchWithConflictingSourceAssociation(mainMatchInfo);
		VTMatch competingMatch = addMatch(matchSet, competingMatchInfo);
		VTAssociation competingAssociation = competingMatch.getAssociation();
		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());
		assertEquals(VTAssociationStatus.AVAILABLE, competingAssociation.getStatus());

		mainAssociation.setAccepted();
		assertEquals(VTAssociationStatus.ACCEPTED, mainAssociation.getStatus());
		assertEquals(VTAssociationStatus.BLOCKED, competingAssociation.getStatus());
	}

	@Test
	public void testClearAccepted_WithNoCompetingAssociations() throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		//
		// The accepted association
		//
		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTAssociation mainAssociation = mainMatch.getAssociation();
		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());

		mainAssociation.setAccepted();
		assertEquals(VTAssociationStatus.ACCEPTED, mainAssociation.getStatus());

		mainAssociation.clearStatus();
		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());
	}

	@Test
	public void testClearAccepted_WithCompetingAssociations() throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		//
		// The accepted association
		//
		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTAssociation mainAssociation = mainMatch.getAssociation();

		//
		// The competition
		//
		VTMatchInfo competingMatchInfo =
			createRandomMatchWithConflictingSourceAssociation(mainMatchInfo);
		VTMatch competingMatch = addMatch(matchSet, competingMatchInfo);
		VTAssociation competingAssociation = competingMatch.getAssociation();
		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());
		assertEquals(VTAssociationStatus.AVAILABLE, competingAssociation.getStatus());

		mainAssociation.setAccepted();
		assertEquals(VTAssociationStatus.ACCEPTED, mainAssociation.getStatus());
		assertEquals(VTAssociationStatus.BLOCKED, competingAssociation.getStatus());

		mainAssociation.clearStatus();
		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());
		assertEquals(VTAssociationStatus.AVAILABLE, competingAssociation.getStatus());
	}

	@Test
	public void testClearAcceptedFailsWithAppliedMatches() throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		//
		// The accepted association
		//
		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTAssociation mainAssociation = mainMatch.getAssociation();
		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());

		mainAssociation.setAccepted();
		assertEquals(VTAssociationStatus.ACCEPTED, mainAssociation.getStatus());

		VTMarkupItem mainMarkupItem = createRandomMarkupItemStub(mainMatch);
		Address destinationAddress = addr();

		mainMarkupItem.setDestinationAddress(destinationAddress);
		try {
			mainMarkupItem.apply(VTMarkupItemApplyActionType.REPLACE, null);
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception applying markup item");// shouldn't happen
		}

		assertEquals(VTMarkupItemStatus.REPLACED, mainMarkupItem.getStatus());

		try {
			mainAssociation.clearStatus();
			Assert.fail("Did not receive the expected exception when trying to clear an accepted " +
				"association that contains applied matches");
		}
		catch (VTAssociationStatusException ase) {
			// good!
		}

		try {
			(mainMarkupItem).unapply();
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception unapplying markup item");// shouldn't happen
		}

		assertEquals(VTAssociationStatus.ACCEPTED, mainAssociation.getStatus());
	}

	@Test
	public void testAcceptingAnEmptyAssociationSetsTheFullyAppliedStatus() throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTAssociation mainAssociation = mainMatch.getAssociation();
		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());

		mainAssociation.setAccepted();
		assertEquals(VTAssociationStatus.ACCEPTED, mainAssociation.getStatus());

		VTAssociationStatus appliedStatus = mainAssociation.getStatus();
		assertEquals("Setting an association accepted did not trigger the applied status to be " +
			VTAssociationStatus.ACCEPTED + " when that association contained no " + "markup items",
			VTAssociationStatus.ACCEPTED, appliedStatus);
	}

	@Test
	public void testTriggeringPartiallyAppliedStatus() throws Exception {
		//
		// Create a match and add a couple markup items
		//
		VTMatch match = createMatchSetWithOneMatch();

		VTMarkupItem markupItem = createRandomMarkupItemStub(match, addr());// first item
		createRandomMarkupItemStub(match, addr());// second item

		VTAssociation association = match.getAssociation();
		Collection<VTMarkupItem> items =
			association.getMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals("Did not find multiple markup items as expected", 2, items.size());
		VTMarkupItemApplyActionType applyAction = createRandomSuccessfulApplyAction(markupItem);

		// ...now apply one item
		Address destinationAddress = addr();
		VTMarkupItem unappliedMarkupItem = markupItem;
		unappliedMarkupItem.setDestinationAddress(destinationAddress);
		try {

			unappliedMarkupItem.apply(applyAction, null);
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception applying markup item");
		}

		Collection<VTMarkupItem> markupItems = getStoredMarkupItems(association);
		assertEquals(1, markupItems.size());
		VTMarkupItem item = markupItems.iterator().next();
		Object obj = getInstanceField("markupItemStorage", item);
		assertTrue("Markup Item from DB is not the correct type",
			(obj instanceof MarkupItemStorageDB));

		// ...make sure the status is partially applied
		assertEquals("Association status was not set to partially applied after we applied " +
			"one markup item", VTAssociationStatus.ACCEPTED, association.getStatus());
	}

	@Test
	public void testTriggeringFullyAppliedStatus() throws Exception {
		//
		// Create a match and add a couple markup items
		//
		VTMatch match = createMatchSetWithOneMatch();

		VTMarkupItem markupItem = createRandomMarkupItemStub(match, addr());// first item
		VTMarkupItem secondAppliedItem = createRandomMarkupItemStub(match, addr());// second item

		VTAssociation association = match.getAssociation();
		Collection<VTMarkupItem> items =
			association.getMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals("Did not find multiple markup items as expected", 2, items.size());
		VTMarkupItemApplyActionType applyAction = createRandomSuccessfulApplyAction(markupItem);

		// ...now apply one item
		Address destinationAddress = addr();
		VTMarkupItem unappliedMarkupItem = markupItem;
		unappliedMarkupItem.setDestinationAddress(destinationAddress);
		try {

			unappliedMarkupItem.apply(applyAction, null);
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception applying markup item");
		}

		Collection<VTMarkupItem> markupItems = getStoredMarkupItems(association);
		assertEquals(1, markupItems.size());
		VTMarkupItem storedMarkupItem = markupItems.iterator().next();
		Object obj = getInstanceField("markupItemStorage", storedMarkupItem);

		assertTrue("Markup Item from DB is not the correct type",
			(obj instanceof MarkupItemStorageDB));
		assertTrue("Status is not applied as expected", storedMarkupItem.canUnapply());

		// ...and make the other item ignored
		applyAction = createRandomSuccessfulApplyAction(secondAppliedItem);
		destinationAddress = addr();
		unappliedMarkupItem = secondAppliedItem;
		unappliedMarkupItem.setDestinationAddress(destinationAddress);
		try {

			unappliedMarkupItem.apply(applyAction, null);
		}
		catch (VersionTrackingApplyException e) {
			Assert.fail("Unexpected exception applying markup item");
		}

		markupItems = getStoredMarkupItems(association);
		assertEquals(2, markupItems.size());
		storedMarkupItem = markupItems.iterator().next();
		assertTrue("Status is not applied as expected", storedMarkupItem.canUnapply());

		// ...now make sure the applied status is 'fully considered'
		assertEquals(
			"Association status was not set to fully applied after we applied " + "one markup item",
			VTAssociationStatus.ACCEPTED, association.getStatus());
	}

	@Test
	public void testVotes() throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTAssociation mainAssociation = mainMatch.getAssociation();

		assertEquals(0, mainAssociation.getVoteCount());
		mainAssociation.setVoteCount(4);
		assertEquals(4, mainAssociation.getVoteCount());

		mainAssociation.setVoteCount(-5);
		assertEquals(0, mainAssociation.getVoteCount());

	}

	@Test
	public void testAssociationHook(@Mocked final AssociationHook mockHook) throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));
		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		final VTAssociation association = mainMatch.getAssociation();

		db.addAssociationHook(mockHook);
		mainMatch.getAssociation().setAccepted();
		mainMatch.getAssociation().clearStatus();

		new Verifications() {
			{
				mockHook.associationAccepted(association);
				mockHook.associationCleared(association);
			}
		};
	}

	@Test
	public void testRejectingAssociation() throws Exception {
		// reject
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTAssociation mainAssociation = mainMatch.getAssociation();
		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());

		mainAssociation.setRejected();
		assertEquals(VTAssociationStatus.REJECTED, mainAssociation.getStatus());

		// unreject
		mainAssociation.clearStatus();

		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());
	}

	@Test
	public void testRejectingAssociation_CannotApplyMarkupItems() throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTAssociation mainAssociation = mainMatch.getAssociation();
		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());

		VTMarkupItem markupItem = VTTestUtils.createRandomMarkupItemStub(mainMatch);
		Collection<VTMarkupItem> items =
			mainAssociation.getMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(1, items.size());

		mainAssociation.setRejected();
		assertEquals(VTAssociationStatus.REJECTED, mainAssociation.getStatus());

		try {
			markupItem.apply(VTMarkupItemApplyActionType.REPLACE, null);
			Assert.fail("We should not be able to apply with a rejected match");
		}
		catch (VersionTrackingApplyException e) {
			// good!
		}
	}

	@Test
	public void testRejectingAssocation_CannotRejectAssociationWithAppliedMarkupItems()
			throws Exception {
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));

		VTMatchInfo mainMatchInfo = createRandomMatch(db);
		VTMatch mainMatch = addMatch(matchSet, mainMatchInfo);
		VTAssociation mainAssociation = mainMatch.getAssociation();
		assertEquals(VTAssociationStatus.AVAILABLE, mainAssociation.getStatus());

		VTMarkupItem markupItem = VTTestUtils.createRandomMarkupItemStub(mainMatch);
		Collection<VTMarkupItem> items =
			mainAssociation.getMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(1, items.size());

		mainAssociation.setAccepted();

		markupItem.setDestinationAddress(addr());
		markupItem.apply(VTMarkupItemApplyActionType.REPLACE, null);

		try {
			mainAssociation.setRejected();
			Assert.fail("Somehow rejected an ACCEPTED association.");
		}
		catch (VTAssociationStatusException e) {
			// good!
		}
	}

	private VTMatchInfo createRandomMatchWithUnrelatedAssociation(VTMatchInfo info) {
		Address sourceAddress = info.getSourceAddress();
		Address destinationAddress = info.getDestinationAddress();
		return createRandomMatch(otherAddr(sourceAddress), otherAddr(destinationAddress), db);
	}

	private VTMatchInfo createRandomMatchWithConflictingDestinationAssociation(VTMatchInfo info) {
		Address destinationAddress = info.getDestinationAddress();
		return createRandomMatch(info.getSourceAddress(), otherAddr(destinationAddress), db);
	}

	private VTMatchInfo createRandomMatchWithConflictingSourceAssociation(VTMatchInfo mainMatch) {
		return createRandomMatch(otherAddr(mainMatch.getSourceAddress()),
			mainMatch.getDestinationAddress(), db);
	}

	private VTMatchInfo createRandomMatchWithSameAssociation(VTMatchInfo mainMatch) {
		return createRandomMatch(mainMatch.getSourceAddress(), mainMatch.getDestinationAddress(),
			db);
	}

	private VTMatch addMatch(VTMatchSet matchSet, VTMatchInfo info) {
		VTMatch newMatch = matchSet.addMatch(info);

		// Odd Code Alert: we don't want the MarkupItemManager actually looking for markup items
		//                 while we are testing, as it is slow.  Thus, we will swap out the real
		//                 implementation for a test dummy.
		VTAssociationDB associationDB = (VTAssociationDB) newMatch.getAssociation();
		setInstanceField("markupManager", associationDB,
			new MarkupItemManagerImplDummy(associationDB));

		return newMatch;
	}

	private VTMatch createMatchSetWithOneMatch() {
		VTMatchInfo match = createRandomMatch(db);
		VTMatchSet matchSet = db.createMatchSet(
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram()));
		return addMatch(matchSet, match);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class MarkupItemManagerImplDummy extends MarkupItemManagerImpl {

		MarkupItemManagerImplDummy(VTAssociationDB associationDB) {
			super(associationDB);
		}

		@Override
		protected Collection<VTMarkupItem> getGeneratedMarkupItems(TaskMonitor monitor)
				throws CancelledException {
			return Collections.emptyList();
		}
	}
}
