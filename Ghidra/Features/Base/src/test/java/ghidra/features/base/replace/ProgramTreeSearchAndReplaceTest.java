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
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;

public class ProgramTreeSearchAndReplaceTest extends AbstractSearchAndReplaceTest {

	@Test
	public void testSearchMemoryBlocks() throws Exception {
		builder.createProgramTree("abc");
		builder.getOrCreateModule("abc", "foo");
		createFragment("abc", "foo", "xxfooxx", 10, 20);

		setSearchTypes(programTrees);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);

		assertEquals(2, results.size());
		sortByName(results);

		assertQuickFix("foo", "bar", results.get(0));
		assertQuickFix("xxfooxx", "xxbarxx", results.get(1));
	}

	@Test
	public void testRenamingProgramTreeModule() throws Exception {
		builder.createProgramTree("abc");
		ProgramModule module = builder.getOrCreateModule("abc", "foo");
		createFragment("abc", "foo", "frag1", 10, 20);

		setSearchTypes(programTrees);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Program Tree Module", item.getItemType());
		assertEquals(new ProgramLocation(program, addr(10)), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());
		assertEquals("bar", module.getName());
	}

	@Test
	public void testRenamingProgramTreeFragment() throws Exception {
		builder.createProgramTree("abc");
		builder.getOrCreateModule("abc", "xxx");
		ProgramFragment fragment = createFragment("abc", "xxx", "foo", 10, 20);

		setSearchTypes(programTrees);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.NONE, item.getStatus());
		assertEquals("Not Applied", item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Program Tree Fragment", item.getItemType());
		assertEquals(new ProgramLocation(program, addr(10)), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.DONE, item.getStatus());
		assertEquals("Applied", item.getStatusMessage());
		assertEquals("bar", item.getCurrent());
		assertEquals("bar", fragment.getName());
	}

	@Test
	public void testRenameModuleDuplicate() throws Exception {
		builder.createProgramTree("abc");
		ProgramModule module = builder.getOrCreateModule("abc", "foo");
		createFragment("abc", "foo", "frag1", 10, 20);
		builder.getOrCreateModule("abc", "bar");
		createFragment("abc", "bar", "frag2", 30, 40);

		setSearchTypes(programTrees);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.WARNING, item.getStatus());
		assertEquals("The name \"bar\" already exists in module \"TestX86\"",
			item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Program Tree Module", item.getItemType());
		assertEquals(new ProgramLocation(program, addr(10)), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.ERROR, item.getStatus());
		assertEquals("Rename Failed! bar already exists", item.getStatusMessage());
		assertEquals("foo", item.getCurrent());
		assertEquals("foo", module.getName());
	}

	@Test
	public void testRenameFragmentDuplicate() throws Exception {
		builder.createProgramTree("abc");
		builder.getOrCreateModule("abc", "module1");
		ProgramFragment fragment = createFragment("abc", "module1", "foo", 10, 20);
		createFragment("abc", "module1", "bar", 30, 40);

		setSearchTypes(programTrees);
		List<QuickFix> results = query("foo", "bar", CASE_SENSITIVE_OFF, WHOLE_WORD_OFF);
		assertEquals(1, results.size());
		QuickFix item = results.get(0);

		assertEquals(QuickFixStatus.WARNING, item.getStatus());
		assertEquals("The name \"bar\" already exists in module \"module1\"",
			item.getStatusMessage());
		assertEquals("Rename", item.getActionName());
		assertEquals("Program Tree Fragment", item.getItemType());
		assertEquals(new ProgramLocation(program, addr(10)), item.getProgramLocation());
		assertEquals("foo", item.getCurrent());

		performAction(item);

		assertEquals(QuickFixStatus.ERROR, item.getStatus());
		assertEquals("Rename Failed! bar already exists", item.getStatusMessage());
		assertEquals("foo", item.getCurrent());
		assertEquals("foo", fragment.getName());
	}

	private ProgramFragment createFragment(String treeName, String moduleName, String fragmentName,
			int start, int end) throws Exception {
		String startAddress = Long.toHexString(start);
		String endAddress = Long.toHexString(end);
		builder.createFragment(treeName, moduleName, fragmentName, startAddress, endAddress);
		Group[] children = program.getListing().getRootModule(treeName).getChildren();
		for (Group group : children) {
			if (group.getName().equals(moduleName) && group instanceof ProgramModule module) {
				Group[] grandChildren = module.getChildren();
				for (Group child : grandChildren) {
					if (child.getName().equals(fragmentName) &&
						child instanceof ProgramFragment fragment) {
						return fragment;
					}
				}
			}
		}
		return null;
	}

}
