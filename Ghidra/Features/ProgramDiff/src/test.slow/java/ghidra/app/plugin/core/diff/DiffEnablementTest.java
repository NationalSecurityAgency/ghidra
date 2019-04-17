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
package ghidra.app.plugin.core.diff;

import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.program.model.address.AddressSet;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public class DiffEnablementTest extends DiffTestAdapter {

	public DiffEnablementTest() {
		super();
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		programBuilderDiffTest1.createMemory("d4", "0x400", 0x100);
//		programBuilderDiffTest1.createComment("0x1001010", "Hey", CodeUnit.EOL_COMMENT);
		programBuilderDiffTest2.createMemory("d2", "0x200", 0x100);

		openDiff(diffTestP1, diffTestP2);

	}

	@Test
	public void testNoSelectionDiffEnablement() {
		// Check action enablement. 
		assertTrue(viewDiffs.isEnabled());
		assertTrue(!applyDiffs.isEnabled());
		assertTrue(!applyDiffsNext.isEnabled());
		assertTrue(!ignoreDiffs.isEnabled());
		assertTrue(nextDiff.isEnabled());
		assertTrue(!prevDiff.isEnabled());
		assertTrue(diffDetails.isEnabled());
		assertTrue(diffApplySettings.isEnabled());
		assertTrue(getDiffs.isEnabled());
		assertTrue(selectAllDiffs.isEnabled());
		assertTrue(!setPgm2Selection.isEnabled());
	}

	@Test
	public void testSelectFirstDiffEnablement() {
		ProgramSelection sel = new ProgramSelection(addr("100"), addr("110"));
		setDiffSelection(sel);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));

		tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(program,
			addr("100")), program));

		// Check action enablement. 
		assertTrue(viewDiffs.isEnabled());
		assertTrue(applyDiffs.isEnabled());
		assertTrue(applyDiffsNext.isEnabled());
		assertTrue(ignoreDiffs.isEnabled());
		assertTrue(nextDiff.isEnabled());
		assertTrue(!prevDiff.isEnabled());
		assertTrue(diffDetails.isEnabled());
		assertTrue(diffApplySettings.isEnabled());
		assertTrue(getDiffs.isEnabled());
		assertTrue(selectAllDiffs.isEnabled());
		assertTrue(setPgm2Selection.isEnabled());
	}

	@Test
	public void testSelectLastDiffEnablement() {
		ProgramSelection sel = new ProgramSelection(addr("1005e4f"), addr("1004e53"));
		setDiffSelection(sel);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));

		tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(program,
			addr("1005e4f")), program));

		// Check action enablement.
		assertTrue(viewDiffs.isEnabled());
		assertTrue(applyDiffs.isEnabled());
		assertTrue(!applyDiffsNext.isEnabled());
		assertTrue(ignoreDiffs.isEnabled());
		assertTrue(!nextDiff.isEnabled());
		assertTrue(prevDiff.isEnabled());
		assertTrue(diffDetails.isEnabled());
		assertTrue(diffApplySettings.isEnabled());
		assertTrue(getDiffs.isEnabled());
		assertTrue(selectAllDiffs.isEnabled());
		assertTrue(setPgm2Selection.isEnabled());
	}

	@Test
	public void testSelectInnerDiffBlockEnablement() {
		ProgramSelection sel = new ProgramSelection(addr("10018ce"), addr("10018cf"));
		setDiffSelection(sel);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));

		tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(program,
			addr("1002347")), program));

		// Check action enablement.
		assertTrue(viewDiffs.isEnabled());
		assertTrue(applyDiffs.isEnabled());
		assertTrue(applyDiffsNext.isEnabled());
		assertTrue(ignoreDiffs.isEnabled());
		assertTrue(nextDiff.isEnabled());
		assertTrue(prevDiff.isEnabled());
		assertTrue(diffDetails.isEnabled());
		assertTrue(diffApplySettings.isEnabled());
		assertTrue(getDiffs.isEnabled());
		assertTrue(selectAllDiffs.isEnabled());
		assertTrue(setPgm2Selection.isEnabled());
	}

	@Test
	public void testSelectPartialDiffBlockEnablement() {
		ProgramSelection sel = new ProgramSelection(addr("100233f"), addr("2345"));
		setDiffSelection(sel);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));

		tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(program,
			addr("1002345")), program));

		// Check action enablement.
		assertTrue(viewDiffs.isEnabled());
		assertTrue(applyDiffs.isEnabled());
		assertTrue(applyDiffsNext.isEnabled());
		assertTrue(ignoreDiffs.isEnabled());
		assertTrue(nextDiff.isEnabled());
		assertTrue(prevDiff.isEnabled());
		assertTrue(diffDetails.isEnabled());
		assertTrue(diffApplySettings.isEnabled());
		assertTrue(getDiffs.isEnabled());
		assertTrue(selectAllDiffs.isEnabled());
		assertTrue(setPgm2Selection.isEnabled());
	}

	@Test
	public void testSelectMultipleDiffBlockEnablement() {
		AddressSet as = new AddressSet(addr("10018ce"), addr("10018cf"));
		as.addRange(addr("1002040"), addr("1002042"));
		as.addRange(addr("100233c"), addr("1002347"));

		ProgramSelection sel = new ProgramSelection(as);
		setDiffSelection(sel);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));

		tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(program,
			addr("1002040")), program));

		// Check action enablement.
		assertTrue(viewDiffs.isEnabled());
		assertTrue(applyDiffs.isEnabled());
		assertTrue(applyDiffsNext.isEnabled());
		assertTrue(ignoreDiffs.isEnabled());
		assertTrue(nextDiff.isEnabled());
		assertTrue(prevDiff.isEnabled());
		assertTrue(diffDetails.isEnabled());
		assertTrue(diffApplySettings.isEnabled());
		assertTrue(getDiffs.isEnabled());
		assertTrue(selectAllDiffs.isEnabled());
		assertTrue(setPgm2Selection.isEnabled());
	}

	@Test
	public void testSelectAllDiffsEnablement() {
		ProgramSelection sel = new ProgramSelection(addr("1001000"), addr("100f400"));
		setDiffSelection(sel);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("test", sel, program));

		tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(program,
			addr("1002040")), program));

		// Check action enablement.
		assertTrue(viewDiffs.isEnabled());
		assertTrue(applyDiffs.isEnabled());
		assertTrue(applyDiffsNext.isEnabled());
		assertTrue(ignoreDiffs.isEnabled());
		assertTrue(nextDiff.isEnabled());
		assertTrue(prevDiff.isEnabled());
		assertTrue(diffDetails.isEnabled());
		assertTrue(diffApplySettings.isEnabled());
		assertTrue(getDiffs.isEnabled());
		assertTrue(selectAllDiffs.isEnabled());
		assertTrue(setPgm2Selection.isEnabled());
	}

}
