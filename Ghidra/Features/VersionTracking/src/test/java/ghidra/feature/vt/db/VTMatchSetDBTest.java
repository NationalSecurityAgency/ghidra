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
import static org.junit.Assert.*;

import java.util.Collection;
import java.util.Collections;

import org.junit.*;

import ghidra.feature.vt.api.db.*;
import ghidra.feature.vt.api.impl.MarkupItemManagerImpl;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class VTMatchSetDBTest extends VTBaseTestCase {

	private int transactionID;

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		transactionID = db.startTransaction("Test");
	}

	@Override
	@After
	public void tearDown() throws Exception {
		db.endTransaction(transactionID, false);
		db.release(VTTestUtils.class);
	}

	@Test
	public void testAddMatch() throws Exception {
		VTProgramCorrelator correlator =
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram());
		VTMatchSet matchSet = db.createMatchSet(correlator);
		assertNotNull(matchSet);

		// put in a match...
		VTMatchInfo match = createRandomMatch(db);
		matchSet.addMatch(match);

		// ...make sure we can get back the match
		Collection<VTMatch> matches = matchSet.getMatches();
		assertTrue(matches.size() == 1);
		VTMatch matchFromDB = matches.iterator().next();
		assertEquivalent("Match put into DB is not the same as the match we got back", match,
			matchFromDB);
	}

	@Test
	public void testRejectAvailableMatch() throws Exception {
		VTProgramCorrelator correlator =
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram());
		VTMatchSet matchSet = db.createMatchSet(correlator);
		assertNotNull(matchSet);

		// Create a match that is NOT_IGNORED, AVAILABLE, and UNAPPLIED.
		VTMatchInfo matchInfo = createMatch(matchSet);
		VTMatch dbMatch = matchSet.addMatch(matchInfo);
		assertEquals(VTAssociationStatus.AVAILABLE, dbMatch.getAssociation().getStatus());
		assertEquivalent("Match put into DB is not the same as the match we got back", matchInfo,
			dbMatch);

		// ...make sure we can get back the match from the match set.
		Collection<VTMatch> matches = matchSet.getMatches();
		assertTrue(matches.size() == 1);
		VTMatch matchFromDB = matches.iterator().next();
		assertEquivalent("Match put into DB is not the same as the match we got back", matchInfo,
			matchFromDB);

		// Set the match to ignored.
		matchFromDB.getAssociation().setRejected();

		matches = matchSet.getMatches();
		assertTrue(matches.size() == 1);
		matchFromDB = matches.iterator().next();
		assertEquals(VTAssociationStatus.REJECTED, dbMatch.getAssociation().getStatus());
	}

	@Test
	public void testRejectAcceptedMatchFailure() throws Exception {
		VTProgramCorrelator correlator =
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram());
		VTMatchSet matchSet = db.createMatchSet(correlator);
		assertNotNull(matchSet);

		// Create a match that is AVAILABLE.
		VTMatchInfo matchInfo = createMatch(matchSet);
		VTMatch dbMatch = matchSet.addMatch(matchInfo);
		VTAssociationDB associationDB = (VTAssociationDB) dbMatch.getAssociation();
		setInstanceField("markupManager", associationDB,
			new MarkupItemManagerImplDummy(associationDB));

		assertEquals(VTAssociationStatus.AVAILABLE, dbMatch.getAssociation().getStatus());
		assertEquivalent("Match put into DB is not the same as the match we got back", matchInfo,
			dbMatch);

		VTAssociationDB association = (VTAssociationDB) dbMatch.getAssociation();
		association.setStatus(VTAssociationStatus.ACCEPTED);
		assertEquals(VTAssociationStatus.ACCEPTED, association.getStatus());

		// ...make sure we can get back the match from the match set.
		Collection<VTMatch> matches = matchSet.getMatches();
		assertTrue(matches.size() == 1);
		VTMatch matchFromDB = matches.iterator().next();
		assertEquivalent("Match put into DB is not the same as the match we got back", matchInfo,
			matchFromDB);

		// Set the match to rejected.
		try {
			matchFromDB.getAssociation().setRejected();
			Assert.fail("Expeced exception when rejected accepted association");
		}
		catch (VTAssociationStatusException e) {
			// expected exception here
		}

		matches = matchSet.getMatches();
		assertTrue(matches.size() == 1);
		matchFromDB = matches.iterator().next();
		assertEquals(VTAssociationStatus.ACCEPTED, dbMatch.getAssociation().getStatus());
	}

	@Test
	public void testRejectBlockedMatch() throws Exception {
		VTProgramCorrelator correlator =
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram());
		VTMatchSet matchSet = db.createMatchSet(correlator);
		assertNotNull(matchSet);

		VTMatchDB lockedOutMatch = createLockedOutMatch(matchSet);

		// Set the match to ignored.
		lockedOutMatch.getAssociation().setRejected();

		// ...make sure we can get back the match from the match set.
		Collection<VTMatch> matches = matchSet.getMatches(lockedOutMatch.getAssociation());
		assertTrue(matches.size() == 1);
		VTMatch matchFromDB = matches.iterator().next();

		assertEquals(VTAssociationStatus.REJECTED, matchFromDB.getAssociation().getStatus());
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertEquivalent(String failureMessage, VTMatchInfo info, VTMatch match) {
		VTAssociation association = match.getAssociation();
		assertTrue(failureMessage,
			info.getSourceAddress().equals(association.getSourceAddress()) &&
				info.getDestinationAddress().equals(association.getDestinationAddress()) &&
				info.getConfidenceScore().equals(match.getConfidenceScore()) &&
				info.getDestinationLength() == match.getDestinationLength() &&
				info.getSimilarityScore().equals(match.getSimilarityScore()) &&
				info.getSourceLength() == match.getSourceLength());
	}

	private VTMatchInfo createMatch(VTMatchSet matchSet) {
		VTMatchInfo match = new VTMatchInfo(matchSet);
		match.setSourceAddress(addr());
		match.setDestinationAddress(addr());
		match.setDestinationLength(getRandomInt());
		match.setSourceLength(getRandomInt());
		match.setSimilarityScore(new VTScore(getRandomInt()));
		match.setConfidenceScore(new VTScore(getRandomInt()));
		match.setAssociationType(getRandomType());
		match.setTag(getRandomTag(db));
		return match;
	}

	private VTMatchDB createLockedOutMatch(VTMatchSet matchSet) throws Exception {
		// Create a match that is NOT_IGNORED, AVAILABLE, and UNAPPLIED.
		VTMatchInfo matchInfo = createMatch(matchSet);
		VTMatchDB dbMatch = (VTMatchDB) matchSet.addMatch(matchInfo);
		VTAssociationDB associationDB = (VTAssociationDB) dbMatch.getAssociation();
		setInstanceField("markupManager", associationDB,
			new MarkupItemManagerImplDummy(associationDB));

		// Created RelatedMatch with same source address.
		VTMatchInfo relatedMatch = createMatch(matchSet);
		relatedMatch.setSourceAddress(dbMatch.getAssociation().getSourceAddress());
		VTMatchDB dbRelatedMatch = (VTMatchDB) matchSet.addMatch(relatedMatch);
		VTAssociationDB relatedAssociationDB = (VTAssociationDB) dbRelatedMatch.getAssociation();
		setInstanceField("markupManager", relatedAssociationDB,
			new MarkupItemManagerImplDummy(relatedAssociationDB));
		relatedAssociationDB.setAccepted();

		Collection<VTMatch> matches2 =
			((VTMatchSetDB) matchSet).getMatches(dbMatch.getAssociation());
		assertTrue(matches2.size() == 1);
		VTMatch matchFromDB2 = matches2.iterator().next();
		VTAssociation association2 = matchFromDB2.getAssociation();
		VTAssociationStatus appliedStatus2 = association2.getStatus();
		assertEquals(VTAssociationStatus.BLOCKED, appliedStatus2);
		return dbMatch;
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
