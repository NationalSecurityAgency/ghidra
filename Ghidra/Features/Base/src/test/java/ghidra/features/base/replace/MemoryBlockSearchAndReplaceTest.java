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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.MemoryBlockStartFieldLocation;

public class MemoryBlockSearchAndReplaceTest extends AbstractSearchAndReplaceTest {
	@Test
	public void testSearchMemoryBlocks() throws Exception {

		createBlock("foo", 0x10000);
		createBlock("xxfooxx", 0x20000);

		setSearchTypes(memoryBlocks);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(2, results.size());
		sortByName(results);

		assertQuickFix(0x10000, "foo", "bar", results.get(0));
		assertQuickFix(0x20000, "xxfooxx", "xxbarxx", results.get(1));
	}

	@Test
	public void testRenamingMemoryBlock() throws Exception {
		MemoryBlock foo = createBlock("foo", 0x10000);

		setSearchTypes(memoryBlocks);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Memory Block", item.getItemType());
		assertEquals(new MemoryBlockStartFieldLocation(program, addr(0x10000), null, 0, 0, null, 0),
			item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());
		assertEquals("bar", foo.getName());
	}

	@Test
	public void testRenameMemoryBlockDuplicateOk() throws Exception {
		MemoryBlock foo = createBlock("foo", 0x10000);
		createBlock("bar", 0x20000);

		setSearchTypes(memoryBlocks);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_ON);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Memory Block", item.getItemType());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());
		assertEquals("bar", foo.getName());
	}

}
