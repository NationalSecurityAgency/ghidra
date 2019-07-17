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

import static org.junit.Assert.*;

import java.util.Set;

import org.junit.*;

import ghidra.feature.vt.api.db.VTMatchTagDB;
import ghidra.feature.vt.api.main.VTMatchInfo;
import ghidra.feature.vt.api.main.VTMatchTag;

public class VTMatchTagDBTest extends VTBaseTestCase {

	private int testTransactionID;

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		testTransactionID = db.startTransaction("Test Match Tags");
	}

	@Override
	@After
	public void tearDown() throws Exception {
		db.endTransaction(testTransactionID, false);
		db.release(VTTestUtils.class);

	}

	@Test
	public void testMatchTagGetAndSet() throws Exception {

		VTMatchInfo matchInfo = createRandomMatch(db);
		VTMatchTag tag = matchInfo.getTag();
		assertNotNull(tag);
		VTMatchTagDB doLaterMatchTag = db.createMatchTag("Do Later");
		matchInfo.setTag(VTMatchTag.UNTAGGED);
		assertEquals(VTMatchTag.UNTAGGED, matchInfo.getTag());
		matchInfo.setTag(doLaterMatchTag);
		assertEquals(doLaterMatchTag, matchInfo.getTag());
	}

	@Test
	public void testGetAllMatchTags() throws Exception {

		VTMatchTagDB doLaterMatchTag = db.createMatchTag("Do Later");
		VTMatchTagDB ignoreMatchTag = db.createMatchTag("Ignore");
		VTMatchTagDB markMatchTag = db.createMatchTag("Mark");
		Set<VTMatchTag> matchTags = db.getMatchTags();
		assertEquals(3, matchTags.size());
		assertTrue(matchTags.contains(doLaterMatchTag));
		assertTrue(matchTags.contains(ignoreMatchTag));
		assertTrue(matchTags.contains(markMatchTag));
	}

	@Test
	public void testGetMatchTagWithKey() throws Exception {

		db.createMatchTag("Do Later");
		VTMatchTagDB ignoreMatchTag = db.createMatchTag("Ignore");
		db.createMatchTag("Mark");
		VTMatchTag matchTag = db.getMatchTag(ignoreMatchTag.getKey());
		assertNotNull(matchTag);
		assertEquals(ignoreMatchTag, matchTag);
	}

	@Test
	public void testGetMatchTagWithKey2() throws Exception {

		VTMatchInfo matchInfo = createRandomMatch(db);
		VTMatchTag tag = matchInfo.getTag();
		assertNotNull(tag);
		long key = ((VTMatchTagDB) tag).getKey();
		assertEquals(tag, db.getMatchTag(key));
	}

	@Test
	public void testMatchTagGetOrCreate() throws Exception {

		VTMatchTag tag = new VTMatchTag() {

			@Override
			public String getName() {
				return "Stuff";
			}

			@Override
			public int compareTo(VTMatchTag o) {
				return getName().compareTo(o.getName());
			}
		};
		VTMatchTagDB matchTagDB = db.getOrCreateMatchTagDB(tag);
		assertEquals("Stuff", matchTagDB.getName());
	}
}
