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
package ghidra.feature.vt.gui.filters;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;

import org.junit.*;

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.impl.VTChangeManager;
import ghidra.feature.vt.api.impl.VersionTrackingChangeRecord;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.db.DummyTestProgramCorrelator;
import ghidra.feature.vt.db.VTBaseTestCase;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTControllerListener;
import ghidra.framework.data.DummyDomainObject;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import mockit.*;

public class TagFilterTest extends VTBaseTestCase {
	@Mocked
	VTController controller;
	@Mocked
	DomainFile domainFile;

	private TagFilter tagFilter;
	private TestTagFilterChooser excludedTagChooser;

	private VTControllerListener listener;

	public TagFilterTest() {
		super();
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		controller = createController();
		excludedTagChooser = new TestTagFilterChooser();
		tagFilter = new TagFilter(controller, excludedTagChooser);
	}

	@Override
	@After
	public void tearDown() throws Exception {
		tagFilter.dispose();
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testFilterWithNoTags() {
		// 
		// test that a match set with no tags applied has no items filtered
		//
		VTSession session = controller.getSession();
		List<VTMatchSet> matchSets = session.getMatchSets();
		VTMatchSet matchSet = matchSets.get(0);
		Collection<VTMatch> matches = matchSet.getMatches();
		for (VTMatch match : matches) {
			assertTrue("Match does not pass empty filter", tagFilter.passesFilter(match));
		}

		FilterState filterState = tagFilter.getFilterState();
		Map<String, VTMatchTag> excludedTags =
			(Map<String, VTMatchTag>) filterState.get(TagFilter.EXCLUDED_TAGS_KEY);
		assertTrue("Have excluded tags when no tags exist", excludedTags.isEmpty());
	}

	@Test
	public void testFilterWithTagsButNoFilterApplied() {
		//
		// Test all matches pass the default filter when some matches have are tagged
		//
		VTSession session = controller.getSession();
		List<VTMatchSet> matchSets = session.getMatchSets();
		VTMatchSet matchSet = matchSets.get(0);
		Collection<VTMatch> matches = matchSet.getMatches();
		Iterator<VTMatch> iterator = matches.iterator();

		int transactionID = startTransaction(session);
		for (int i = 0; i < matches.size(); i++) {
			VTMatch match = iterator.next();
			if (i % 2 == 0) {
				// don't tag all matches
				continue;
			}
			match.setTag(new TestMatchTag());
		}
		endTransaction(session, transactionID);

		for (VTMatch match : matches) {
			assertTrue("Match does not pass empty filter", tagFilter.passesFilter(match));
		}
	}

	@Test
	public void testMatchesPassFilterWithIncludedTags() {
		//
		// Test that an applied filter will include only those tags chosen to pass the filter
		// 
		VTMatchTag fooTag = new TestMatchTag("Foo");
		VTMatchTag barTag = new TestMatchTag("Bar");
		VTMatchTag bazTag = new TestMatchTag("Baz");

		VTSession session = controller.getSession();
		List<VTMatchSet> matchSets = session.getMatchSets();
		VTMatchSet matchSet = matchSets.get(0);
		Collection<VTMatch> matches = matchSet.getMatches();
		List<VTMatch> matchesList = new ArrayList<>(matches);
		VTMatch fooTagMatch1 = matchesList.get(0);
		VTMatch barTagMatch1 = matchesList.get(1);
		VTMatch bazTagMatch1 = matchesList.get(2);
		VTMatch fooTagMatch2 = matchesList.get(3);
		VTMatch barTagMatch2 = matchesList.get(4);
		VTMatch bazTagMatch2 = matchesList.get(5);
		VTMatch untaggedMatch1 = matchesList.get(6);
		VTMatch untaggedMatch2 = matchesList.get(7);

		int transactionID = startTransaction(session);
		fooTagMatch1.setTag(fooTag);
		fooTagMatch2.setTag(fooTag);
		barTagMatch1.setTag(barTag);
		barTagMatch2.setTag(barTag);
		bazTagMatch1.setTag(bazTag);
		bazTagMatch2.setTag(bazTag);
		untaggedMatch1.setTag(null);
		untaggedMatch2.setTag(null);
		endTransaction(session, transactionID);

		excludedTagChooser.setExcludedTags(barTag, bazTag);
		chooseFilteredTags();

		assertPassesFilter(fooTagMatch1, fooTagMatch2, untaggedMatch1, untaggedMatch2);
		assertDoesNotPassFilter(barTagMatch1, barTagMatch2, bazTagMatch1, bazTagMatch2);

		excludedTagChooser.setExcludedTags(fooTag);
		chooseFilteredTags();

		assertPassesFilter(barTagMatch1, barTagMatch2, bazTagMatch1, bazTagMatch2, untaggedMatch1,
			untaggedMatch2);
		assertDoesNotPassFilter(fooTagMatch1, fooTagMatch2);
	}

	@Test
	public void testFilterUpdateForTagAdded() throws IOException {
		//
		// Test that we can apply a tag filter and that as tags are added the filter
		// will update.
		//
		VTMatchTag fooTag = new TestMatchTag("Foo");
		VTMatchTag barTag = new TestMatchTag("Bar");

		VTSession session = controller.getSession();
		List<VTMatchSet> matchSets = session.getMatchSets();
		VTMatchSet matchSet = matchSets.get(0);
		Collection<VTMatch> matches = matchSet.getMatches();
		List<VTMatch> matchesList = new ArrayList<>(matches);
		VTMatch fooTagMatch1 = matchesList.get(0);
		VTMatch barTagMatch1 = matchesList.get(1);
		VTMatch untaggedMatch1 = matchesList.get(2);

		int transactionID = startTransaction(session);
		fooTagMatch1.setTag(fooTag);
		barTagMatch1.setTag(barTag);
		untaggedMatch1.setTag(null);
		endTransaction(session, transactionID);

		excludedTagChooser.setExcludedTags(barTag);
		chooseFilteredTags();

		assertPassesFilter(fooTagMatch1, untaggedMatch1);
		assertDoesNotPassFilter(barTagMatch1);

		// add a new tag and make sure it is excluded and so are the previously excluded tag
		VTMatchTag newTag = new TestMatchTag("New Tag");
		VTMatch updatedMatch = matchesList.get(3);
		transactionID = startTransaction(session);
		updatedMatch.setTag(newTag);
		endTransaction(session, transactionID);

		notifyTagAdded(newTag);

		// the match with the new tag should pass the filter
		assertPassesFilter(fooTagMatch1, untaggedMatch1, updatedMatch);
	}

	@Test
	public void testFilterUpdateForTagRemoved() throws IOException {
		//
		// Test that we can apply a tag filter and that as tags are removed the filter
		// will update.  Test for both an item that is and isn't filtered out.
		//
		VTMatchTag fooTag = new TestMatchTag("Foo");
		VTMatchTag barTag = new TestMatchTag("Bar");

		VTSession session = controller.getSession();
		List<VTMatchSet> matchSets = session.getMatchSets();
		VTMatchSet matchSet = matchSets.get(0);
		Collection<VTMatch> matches = matchSet.getMatches();
		List<VTMatch> matchesList = new ArrayList<>(matches);
		VTMatch fooTagMatch1 = matchesList.get(0);
		VTMatch barTagMatch1 = matchesList.get(1);
		VTMatch untaggedMatch1 = matchesList.get(2);

		int transactionID = startTransaction(session);
		fooTagMatch1.setTag(fooTag);
		barTagMatch1.setTag(barTag);
		untaggedMatch1.setTag(null);
		endTransaction(session, transactionID);

		assertPassesFilter(fooTagMatch1, untaggedMatch1, barTagMatch1);

		String tagName = barTag.getName();
		transactionID = startTransaction(session);
		session.deleteMatchTag(barTag);
		endTransaction(session, transactionID);

		notifyTagRemoved(tagName);

		assertPassesFilter(fooTagMatch1, untaggedMatch1, barTagMatch1);

		// 
		// now filter out an item and then remove that item
		//
		excludedTagChooser.setExcludedTags(fooTag);
		chooseFilteredTags();

		assertPassesFilter(barTagMatch1, untaggedMatch1);
		assertDoesNotPassFilter(fooTagMatch1);

		tagName = fooTag.getName();
		transactionID = startTransaction(session);
		session.deleteMatchTag(fooTag);
		endTransaction(session, transactionID);

		// now that the tag has been removed, the 'foo' match should again pass
		assertPassesFilter(fooTagMatch1, untaggedMatch1, barTagMatch1);
	}

	@Test
	public void testFilterRemembersIncludedTags() {
		//
		// Test that we can get and set the state of the filter
		//
		VTMatchTag fooTag = new TestMatchTag("Foo");
		VTMatchTag barTag = new TestMatchTag("Bar");

		VTSession session = controller.getSession();
		List<VTMatchSet> matchSets = session.getMatchSets();
		VTMatchSet matchSet = matchSets.get(0);
		Collection<VTMatch> matches = matchSet.getMatches();
		List<VTMatch> matchesList = new ArrayList<>(matches);
		VTMatch fooTagMatch1 = matchesList.get(0);
		VTMatch barTagMatch1 = matchesList.get(1);

		int transactionID = startTransaction(session);
		fooTagMatch1.setTag(fooTag);
		barTagMatch1.setTag(barTag);
		endTransaction(session, transactionID);

		excludedTagChooser.setExcludedTags(barTag);
		chooseFilteredTags();

		assertPassesFilter(fooTagMatch1);
		assertDoesNotPassFilter(barTagMatch1);

		FilterState filterState = tagFilter.getFilterState();
		tagFilter.restoreFilterState(filterState);

		assertPassesFilter(fooTagMatch1);
		assertDoesNotPassFilter(barTagMatch1);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void chooseFilteredTags() {
		invokeInstanceMethod("chooseExcludedTags", tagFilter);
	}

	private int startTransaction(VTSession session) {
		return ((VTSessionDB) session).startTransaction("Test Transaction");
	}

	private void endTransaction(VTSession session, int transactionID) {
		((VTSessionDB) session).endTransaction(transactionID, true);
	}

	private void assertPassesFilter(VTMatch... matches) {
		for (VTMatch match : matches) {
			assertTrue("Match did not pass filter", tagFilter.passesFilter(match));
		}
	}

	private void assertDoesNotPassFilter(VTMatch... matches) {
		for (VTMatch match : matches) {
			assertTrue("Match passed filter when its tag is excluded: " + match,
				!tagFilter.passesFilter(match));
		}
	}

	private void notifyTagAdded(VTMatchTag newTag) throws IOException {
		List<DomainObjectChangeRecord> subEvents = new ArrayList<>();
		subEvents.add(new VersionTrackingChangeRecord(VTChangeManager.DOCR_VT_TAG_ADDED, newTag,
			null, newTag));
		listener.sessionUpdated(
			new DomainObjectChangedEvent(new DummyDomainObject(this), subEvents));
	}

	private void notifyTagRemoved(String tagName) throws IOException {
		List<DomainObjectChangeRecord> subEvents = new ArrayList<>();
		subEvents.add(new VersionTrackingChangeRecord(VTChangeManager.DOCR_VT_TAG_REMOVED, null,
			tagName, null));
		listener.sessionUpdated(
			new DomainObjectChangedEvent(new DummyDomainObject(this), subEvents));
	}

	// controller creation
	private VTController createController() {
		final VTSession session = createSession();

		new Expectations() {
			{
				controller.addListener(with(new ListenerDelegate()));
				controller.getSession();
				result = session;
			}
		};

		return controller;
	}

	class ListenerDelegate implements Delegate<VTControllerListener> {
		void validate(VTControllerListener l) {
			listener = l;
		}
	}

	private VTSessionDB createSession() {

		// add some matches
		int testTransactionID = 0;
		try {
			testTransactionID = db.startTransaction("Test Match Set Setup");
			for (int i = 0; i < 10; i++) {
				createMatch(db);
			}
		}
		finally {
			db.endTransaction(testTransactionID, true);
		}

		return db;
	}

	private VTMatch createMatch(VTSessionDB sessionDb) {
		VTMatchInfo matchInfo = createRandomMatch(addr(), addr(), sessionDb);
		List<VTMatchSet> matchSets = sessionDb.getMatchSets();
		if (matchSets.size() == 0) {
			sessionDb.createMatchSet(createProgramCorrelator(null, sessionDb.getSourceProgram(),
				sessionDb.getDestinationProgram()));
			matchSets = sessionDb.getMatchSets();
		}

		return matchSets.get(0).addMatch(matchInfo);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TestMatchTag implements VTMatchTag {

		private String name;

		TestMatchTag() {
			name = getRandomString(1, 20);
			assertFalse(name.isEmpty());
		}

		TestMatchTag(String name) {
			this.name = name;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public int compareTo(VTMatchTag o) {
			return getName().compareTo(o.getName());
		}
	}

	private class TestTagFilterChooser implements TagFilterChooser {
		private Map<String, VTMatchTag> excludedTags;

		private void setExcludedTags(VTMatchTag... tags) {
			excludedTags = new HashMap<>();
			for (VTMatchTag tag : tags) {
				excludedTags.put(tag.getName(), tag);
			}
		}

		@Override
		public Map<String, VTMatchTag> getExcludedTags(Map<String, VTMatchTag> allTags,
				Map<String, VTMatchTag> currentExcludedTags) {
			return excludedTags;
		}
	}

	public static VTProgramCorrelator createProgramCorrelator(ServiceProvider serviceProvider,
			Program sourceProgram, Program destinationProgram) {
		return new DummyTestProgramCorrelator(serviceProvider, sourceProgram, destinationProgram);
	}

}
