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
import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.*;

import generic.timer.GhidraTimer;
import ghidra.feature.vt.api.db.VTMatchTagDB;
import ghidra.feature.vt.api.impl.VTChangeManager;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.VTAssociationStatusException;
import ghidra.framework.model.*;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import mockit.Mock;
import mockit.MockUp;

public class VTDomainObjectEventsTest extends VTBaseTestCase {

	private int transactionID;
	private volatile List<DomainObjectChangeRecord> events = new ArrayList<>();

	private DomainObjectListener listener = new DomainObjectListener() {
		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			Msg.debug(this,
				"domainObjectChanged(): from thread " + Thread.currentThread().getName());
			for (DomainObjectChangeRecord record : ev) {
				Msg.debug(this, "\tadding record: " + record.getEventType());
				events.add(record);
			}
			Msg.debug(this, "\tfinished adding records");
		}
	};

	public VTDomainObjectEventsTest() {
		super();
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		Msg.debug(this, "\n\nsetUp(): " + testName.getMethodName());
		transactionID = db.startTransaction("Test");

		db.addListener(listener);

		disableDocsTimer();

		clearEvents();
	}

	private <T extends GhidraTimer> void disableDocsTimer() {
		// The DomainObjectChangeSupport class uses a timer.  In SOP, the timer fires its 
		// events on the Swing thread.
		// We are in a headless environment.  Resultingly, we cannot use the Swing thread to
		// synchronize events when we flush them.  Here we mock the timer, preventing it 
		// from starting. Without the timer, we can rely on our flushing of the queued events.

		new MockUp<T>() {
			@Mock
			public void start() {
				// never let the timer start
			}
		};

	}

	@Override
	@After
	public void tearDown() throws Exception {
		Msg.debug(this, "tearDown()\n");
		db.endTransaction(transactionID, false);
		db.release(VTTestUtils.class);
	}

	@Test
	public void testEventForCreatingMatchSet() {
		createMatchSet();

		assertEventCount(1);
		assertEquals(VTChangeManager.DOCR_VT_MATCH_SET_ADDED, events.get(0).getEventType());
	}

	@Test
	public void testEventsForAddingFirstMatchForAssociation() {
		VTMatchSet matchSet = createMatchSet();
		clearEvents();
		VTMatchInfo match = VTTestUtils.createRandomMatch(null);

		matchSet.addMatch(match);

		assertEventCount(2);
		assertEquals(VTChangeManager.DOCR_VT_ASSOCIATION_ADDED, events.get(0).getEventType());
		assertEquals(VTChangeManager.DOCR_VT_MATCH_ADDED, events.get(1).getEventType());
	}

	@Test
	public void testEventsForAddingAdditionalMatchForAssociation() {
		VTMatchSet matchSet = createMatchSet();
		VTMatchInfo matchInfo = VTTestUtils.createRandomMatch(null);
		matchSet.addMatch(matchInfo);
		clearEvents();

		matchInfo = VTTestUtils.createRandomMatch(matchInfo.getSourceAddress(),
			matchInfo.getDestinationAddress(), null);
		matchSet.addMatch(matchInfo);

		assertEventCount(1);
		assertEquals(VTChangeManager.DOCR_VT_MATCH_ADDED, events.get(0).getEventType());
	}

	@Test
	public void testEventsForRemovingLastMatchForAssociation() {
		VTMatchSet manualMatchSet = db.getManualMatchSet();
		clearEvents();
		VTMatchInfo matchInfo = VTTestUtils.createRandomMatch(null);
		VTMatch match = manualMatchSet.addMatch(matchInfo);
		clearEvents();

		manualMatchSet.removeMatch(match);

		assertEventCount(2);
		assertEquals(VTChangeManager.DOCR_VT_ASSOCIATION_REMOVED, events.get(0).getEventType());
		assertEquals(VTChangeManager.DOCR_VT_MATCH_DELETED, events.get(1).getEventType());
	}

	@Test
	public void testEventsForRemovingNonLastMatchForAssociation() {
		VTMatchSet manualMatchSet = db.getManualMatchSet();
		clearEvents();
		VTMatchInfo matchInfo = VTTestUtils.createRandomMatch(null);
		VTMatch match = manualMatchSet.addMatch(matchInfo);
		clearEvents();

		manualMatchSet.removeMatch(match);

		assertEventCount(2);
		assertEquals(VTChangeManager.DOCR_VT_ASSOCIATION_REMOVED, events.get(0).getEventType());
		assertEquals(VTChangeManager.DOCR_VT_MATCH_DELETED, events.get(1).getEventType());
	}

	@Test
	public void testEventsForRejectingMatch() throws VTAssociationStatusException {
		VTMatchSet matchSet = createMatchSet();
		VTMatchInfo matchInfo = VTTestUtils.createRandomMatch(null);
		VTMatch match = matchSet.addMatch(matchInfo);
		clearEvents();
		match.getAssociation().setRejected();

		assertEventCount(1);
		assertEquals(VTChangeManager.DOCR_VT_ASSOCIATION_STATUS_CHANGED,
			events.get(0).getEventType());
	}

	@Test
	public void testAssociationStatusChangedEvent() throws Exception {
		VTMatchSet manualMatchSet = db.getManualMatchSet();
		clearEvents();
		VTMatchInfo matchInfo = VTTestUtils.createRandomMatch(null);
		VTMatch match = manualMatchSet.addMatch(matchInfo);
		clearEvents();

		match.getAssociation().setAccepted();

		assertEventCount(1);
		assertEquals(VTChangeManager.DOCR_VT_ASSOCIATION_STATUS_CHANGED,
			events.get(0).getEventType());
	}

	@Test
	public void testMarkupDestinationAddressChangedEvent() throws Exception {
		Msg.debug(this, "\tcalling getManualMatchSet()");
		VTMatchSet manualMatchSet = db.getManualMatchSet();
		Msg.debug(this, "\tcalling clrearEvents()");
		clearEvents();
		Msg.debug(this, "\tcalling createRandomMatch()");
		VTMatchInfo matchInfo = VTTestUtils.createRandomMatch(null);
		Msg.debug(this, "\tcalling addMatch()");
		VTMatch match = manualMatchSet.addMatch(matchInfo);
		Msg.debug(this, "\tcalling setAccepted()");
		match.getAssociation().setAccepted();
		Msg.debug(this, "\tcalling createRandomMarkupItemStub()");
		VTMarkupItem markupItem = VTTestUtils.createRandomMarkupItemStub(match);

		Address destinationAddress = addr();
		Msg.debug(this, "\tcalling clearEvents()");
		clearEvents();

		Msg.debug(this, "\tcalling setDestinationAddress()");
		markupItem.setDestinationAddress(destinationAddress);
		Msg.debug(this, "\t\tafter setDestinationAddress()");
		assertEquals(destinationAddress, markupItem.getDestinationAddress());

		assertEventCount(1);
		assertEquals(VTChangeManager.DOCR_VT_MARKUP_ITEM_DESTINATION_CHANGED,
			events.get(0).getEventType());
	}

	@Test
	public void testMarkupStatusChangedEventWhenApplying() throws Exception {
		VTMatchSet manualMatchSet = db.getManualMatchSet();
		clearEvents();
		VTMatchInfo matchInfo = VTTestUtils.createRandomMatch(null);
		VTMatch match = manualMatchSet.addMatch(matchInfo);
		match.getAssociation().setAccepted();
		VTMarkupItem markupItem = VTTestUtils.createRandomMarkupItemStub(match);

		Address destinationAddress = addr();

		markupItem.setDestinationAddress(destinationAddress);
		clearEvents();

		markupItem.apply(VTMarkupItemApplyActionType.REPLACE, null);

		assertEventCount(1);
		assertEquals(VTChangeManager.DOCR_VT_MARKUP_ITEM_STATUS_CHANGED,
			events.get(0).getEventType());
	}

	@Test
	public void testMarkupStatusChangedEventWhenSettingStatus() throws Exception {
		VTMatchSet manualMatchSet = db.getManualMatchSet();
		clearEvents();
		VTMatchInfo matchInfo = VTTestUtils.createRandomMatch(null);
		VTMatch match = manualMatchSet.addMatch(matchInfo);
		match.getAssociation().setAccepted();
		VTMarkupItem markupItem = VTTestUtils.createRandomMarkupItemStub(match);

		Address destinationAddress = addr();

		markupItem.setDestinationAddress(destinationAddress);
		clearEvents();

		markupItem.setConsidered(VTMarkupItemConsideredStatus.IGNORE_DONT_CARE);

		assertEventCount(1);
		assertEquals(VTChangeManager.DOCR_VT_MARKUP_ITEM_STATUS_CHANGED,
			events.get(0).getEventType());
	}

	@Test
	public void testTagAddedEvent() {
		db.createMatchTag("TEST");
		assertEventCount(1);
		assertEquals(VTChangeManager.DOCR_VT_TAG_ADDED, events.get(0).getEventType());
	}

	@Test
	public void testTagRemovedEvent() {
		VTMatchTagDB tag = db.createMatchTag("TEST");
		clearEvents();
		db.deleteMatchTag(tag);
		assertEventCount(1);
		assertEquals(VTChangeManager.DOCR_VT_TAG_REMOVED, events.get(0).getEventType());
	}

	@Test
	public void testTagAppliedEvent() throws VTAssociationStatusException {
		VTMatchTagDB tag = db.createMatchTag("TEST");
		VTMatchSet manualMatchSet = db.getManualMatchSet();
		VTMatchInfo matchInfo = VTTestUtils.createRandomMatch(null);
		VTMatch match = manualMatchSet.addMatch(matchInfo);
		match.getAssociation().setAccepted();
		clearEvents();
		match.setTag(tag);
		assertEventCount(1);
		assertEquals(VTChangeManager.DOCR_VT_MATCH_TAG_CHANGED, events.get(0).getEventType());

		clearEvents();
		match.setTag(null);
		assertEventCount(1);
		assertEquals(VTChangeManager.DOCR_VT_MATCH_TAG_CHANGED, events.get(0).getEventType());

	}

	@Test
	public void testEventsForVotes() {
		VTMatchSet manualMatchSet = db.getManualMatchSet();
		VTMatchInfo matchInfo = VTTestUtils.createRandomMatch(null);
		VTMatch match = manualMatchSet.addMatch(matchInfo);
		clearEvents();
		match.getAssociation().setVoteCount(4);
		assertEventCount(1);
		assertEquals(VTChangeManager.DOCR_VT_VOTE_COUNT_CHANGED, events.get(0).getEventType());
	}

	private void assertEventCount(int n) {

		waitForCondition(() -> {
			db.flushEvents();
			return events.size() >= n;
		});

		assertEquals("Incorrect numbrer of domain events", n, events.size());
	}

	private void clearEvents() {
		Msg.debug(this, "clearEvents() - event count: " + events.size());
		db.flushEvents();
		Msg.debug(this, "\tafter flushEvents");
		events.clear();
		Msg.debug(this, "\tafter clear");
	}

	private VTMatchSet createMatchSet() {
		VTProgramCorrelator correlator =
			createProgramCorrelator(null, db.getSourceProgram(), db.getDestinationProgram());
		return db.createMatchSet(correlator);
	}
}
