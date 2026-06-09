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

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.quickfix.QuickFixStatus;
import ghidra.program.model.data.CategoryPath;

public class CategoriesSearchAndReplaceTest extends AbstractSearchAndReplaceTest {
	@Test
	public void testSearchCategories() throws Exception {
		builder.addCategory(new CategoryPath("/abc/foo1"));
		builder.addCategory(new CategoryPath("/foo2/xxx"));
		builder.addCategory(new CategoryPath("/abc/xxfoo3xx"));

		setSearchTypes(categories);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(3, results.size());
		sortByName(results);

		assertQuickFix("foo1", "bar1", results.get(0));
		assertQuickFix("foo2", "bar2", results.get(1));
		assertQuickFix("xxfoo3xx", "xxbar3xx", results.get(2));
	}

	@Test
	public void testRenamingCategory() throws Exception {
		builder.addCategory(new CategoryPath("/abc/foo/def"));

		setSearchTypes(categories);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("datatype category", item.getItemType());
		assertEquals(null, item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());
		assertNotNull(program.getDataTypeManager().getCategory(new CategoryPath("/abc/bar")));
	}

	@Test
	public void testRenameCategoryDuplicate() throws Exception {
		builder.addCategory(new CategoryPath("/abc/foo"));
		builder.addCategory(new CategoryPath("/abc/bar"));

		setSearchTypes(categories);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.WARNING, item.getStatus());
		assertEquals("The name \"bar\" already exists in category \"/abc\"",
			item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("datatype category", item.getItemType());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.ERROR, item.getStatus());
		assertEquals("Rename Failed! Category named bar already exists", item.getStatusMessage());
		assertEquals("foo", item.getCurrent());
		assertNotNull(program.getDataTypeManager().getCategory(new CategoryPath("/abc/foo")));
	}

}
