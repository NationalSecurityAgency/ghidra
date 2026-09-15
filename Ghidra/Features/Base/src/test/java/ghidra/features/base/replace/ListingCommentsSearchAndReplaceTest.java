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
package ghidra.features.base.replace;

import static ghidra.program.model.listing.CommentType.*;
import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.quickfix.QuickFixStatus;
import ghidra.program.util.*;

public class ListingCommentsSearchAndReplaceTest extends AbstractSearchAndReplaceTest {

	@Test
	public void testSearchComments() throws Exception {
		createComment(10, EOL, "EOLxxx abcxxxdef");
		createComment(20, PLATE, "PLATE xxx");
		createComment(30, PRE, "xxx PRE");
		createComment(30, POST, "POST abcxxxdef");
		createComment(30, REPEATABLE, "REPEATABLE xxx");

		setSearchTypes(comments);
		List<QuickFix> results = query("xxx", "zzz", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(5, results.size());
		sortByAddress(results);

		assertQuickFix(10, "EOLxxx abcxxxdef", "EOLzzz abczzzdef", results.get(0));
		assertQuickFix(20, "PLATE xxx", "PLATE zzz", results.get(1));
		assertQuickFix(30, "xxx PRE", "zzz PRE", results.get(2));
		assertQuickFix(30, "POST abcxxxdef", "POST abczzzdef", results.get(3));
		assertQuickFix(30, "REPEATABLE xxx", "REPEATABLE zzz", results.get(4));
	}

	@Test
	public void testChangingListingEolComments() throws Exception {
		createComment(10, EOL, "EOL xxx abcxxxdef");

		setSearchTypes(comments);
		List<QuickFix> results = query("xxx", "zzz", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Update", item.getActionName());
		assertEquals("Code Comment", item.getItemType());
		assertEquals(new EolCommentFieldLocation(program, addr(10), null, null, 0, 0, 0),
			item.getProgramLocation());
		assertEquals("EOL xxx abcxxxdef", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("EOL zzz abczzzdef", item.getCurrent());
	}

	@Test
	public void testChangingListingPostComments() throws Exception {
		createComment(10, POST, "POST xxx abcxxxdef");

		setSearchTypes(comments);
		List<QuickFix> results = query("xxx", "zzz", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Update", item.getActionName());
		assertEquals("Code Comment", item.getItemType());
		assertEquals(new PostCommentFieldLocation(program, addr(10), null, null, 0, 0),
			item.getProgramLocation());
		assertEquals("POST xxx abcxxxdef", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("POST zzz abczzzdef", item.getCurrent());
	}

	@Test
	public void testChangingListingPlateComments() throws Exception {
		createComment(10, PLATE, "PLATE xxx abcxxxdef");

		setSearchTypes(comments);
		List<QuickFix> results = query("xxx", "zzz", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Update", item.getActionName());
		assertEquals("Code Comment", item.getItemType());
		assertEquals(new PlateFieldLocation(program, addr(10), null, 0, 0, null, 0),
			item.getProgramLocation());
		assertEquals("PLATE xxx abcxxxdef", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("PLATE zzz abczzzdef", item.getCurrent());
	}

	@Test
	public void testChangingListingRepeatableComments() throws Exception {
		createComment(10, REPEATABLE, "REPEATABLE xxx abcxxxdef");

		setSearchTypes(comments);
		List<QuickFix> results = query("xxx", "zzz", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Update", item.getActionName());
		assertEquals("Code Comment", item.getItemType());
		assertEquals(new RepeatableCommentFieldLocation(program, addr(10), null, null, 0, 0, 0),
			item.getProgramLocation());
		assertEquals("REPEATABLE xxx abcxxxdef", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("REPEATABLE zzz abczzzdef", item.getCurrent());
	}

	@Test
	public void testChangingListingPreComments() throws Exception {
		createComment(10, PRE, "PRE xxx abcxxxdef");

		setSearchTypes(comments);
		List<QuickFix> results = query("xxx", "zzz", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Update", item.getActionName());
		assertEquals("Code Comment", item.getItemType());
		assertEquals(new CommentFieldLocation(program, addr(10), null, null, PRE, 0, 0),
			item.getProgramLocation());
		assertEquals("PRE xxx abcxxxdef", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("PRE zzz abczzzdef", item.getCurrent());
	}

	@Test
	public void testChangingListingCommentsWholeWordOn() throws Exception {
		createComment(10, EOL, "EOL xxx abcxxxdef");

		setSearchTypes(comments);
		List<QuickFix> results = query("xxx", "zzz", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Update", item.getActionName());
		assertEquals("Code Comment", item.getItemType());
		assertEquals(addr(10), item.getProgramLocation().getAddress());
		assertEquals("EOL xxx abcxxxdef", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("EOL zzz abcxxxdef", item.getCurrent());
	}
}
