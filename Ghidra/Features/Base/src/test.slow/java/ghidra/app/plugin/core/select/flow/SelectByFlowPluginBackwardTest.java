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
package ghidra.app.plugin.core.select.flow;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import ghidra.GhidraOptions;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.AddressSet;
import ghidra.program.util.ProgramSelection;

public class SelectByFlowPluginBackwardTest extends AbstractSelectByFlowPluginTest {

	@Test
	public void testFollowAllFlowsBackFromSelection() {

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x131), addr(0x131));
		selectionSet.add(addr(0x161), addr(0x161));
		selectionSet.add(addr(0x191), addr(0x191));
		selectionSet.add(addr(0x231), addr(0x231));
		selectionSet.add(addr(0x261), addr(0x261));
		selectionSet.add(addr(0x291), addr(0x291));
		selectionSet.add(addr(0x331), addr(0x331));
		selectionSet.add(addr(0x361), addr(0x361));
		selectionSet.add(addr(0x391), addr(0x391));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x2e));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x60), addr(0x8e));
		expectedAddresses.add(addr(0x90), addr(0xbe));
		expectedAddresses.add(addr(0x130), addr(0x131));
		expectedAddresses.add(addr(0x160), addr(0x161));
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5000), addr(0x5003));
		expectedAddresses.add(addr(0x5004), addr(0x5007));
		expectedAddresses.add(addr(0x5008), addr(0x500b));
		expectedAddresses.add(addr(0x5024), addr(0x5027));
		expectedAddresses.add(addr(0x5048), addr(0x504b));
		// CodeBrowser expands selection to entire code unit.
		expectedAddresses.add(addr(0x5020), addr(0x502b));
		expectedAddresses.add(addr(0x5040), addr(0x504b));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectAllFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowAllFlowsBackFrom0x2f() {

		goTo(addr(0x2f));

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x2f));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectAllFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testAllLimitedFlowsBackFrom0x8f() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOnAllFollowFlow(flowOptions);

		goTo(addr(0x8f));

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x20));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x60), addr(0x8f));
		expectedAddresses.add(addr(0x5000), addr(0x5003));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testAllLimitedFlowsBackFromEnd() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOnAllFollowFlow(flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x131), addr(0x131));
		selectionSet.add(addr(0x161), addr(0x161));
		selectionSet.add(addr(0x191), addr(0x191));
		selectionSet.add(addr(0x231), addr(0x231));
		selectionSet.add(addr(0x261), addr(0x261));
		selectionSet.add(addr(0x291), addr(0x291));
		selectionSet.add(addr(0x331), addr(0x331));
		selectionSet.add(addr(0x361), addr(0x361));
		selectionSet.add(addr(0x391), addr(0x391));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x2e));
		expectedAddresses.add(addr(0x30), addr(0x5e));
		expectedAddresses.add(addr(0x60), addr(0x8e));
		expectedAddresses.add(addr(0x90), addr(0xbe));
		expectedAddresses.add(addr(0x130), addr(0x131));
		expectedAddresses.add(addr(0x160), addr(0x161));
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5000), addr(0x5003));
		expectedAddresses.add(addr(0x5004), addr(0x5007));
		expectedAddresses.add(addr(0x5008), addr(0x500b));
		expectedAddresses.add(addr(0x5024), addr(0x5027));
		expectedAddresses.add(addr(0x5048), addr(0x504b));
		// CodeBrowser expands selection to entire code unit.
		expectedAddresses.add(addr(0x5020), addr(0x502b));
		expectedAddresses.add(addr(0x5040), addr(0x504b));

		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testNoLimitedFlowsBackFromEnd() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x131), addr(0x131));
		selectionSet.add(addr(0x161), addr(0x161));
		selectionSet.add(addr(0x191), addr(0x191));
		selectionSet.add(addr(0x231), addr(0x231));
		selectionSet.add(addr(0x261), addr(0x261));
		selectionSet.add(addr(0x291), addr(0x291));
		selectionSet.add(addr(0x331), addr(0x331));
		selectionSet.add(addr(0x361), addr(0x361));
		selectionSet.add(addr(0x391), addr(0x391));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x130), addr(0x131));
		expectedAddresses.add(addr(0x160), addr(0x161));
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowBackOnlyUnconditionalCalls() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followUnconditionalCalls(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x0a), addr(0x0a));
		selectionSet.add(addr(0x0e), addr(0x0e));
		selectionSet.add(addr(0x0f), addr(0x0f));
		selectionSet.add(addr(0x26), addr(0x26));
		selectionSet.add(addr(0x30), addr(0x30));
		selectionSet.add(addr(0x60), addr(0x60));
		selectionSet.add(addr(0x90), addr(0x90));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0a), addr(0x0a));
		expectedAddresses.add(addr(0x0e), addr(0x0e));
		expectedAddresses.add(addr(0x0f), addr(0x15));
		expectedAddresses.add(addr(0x25), addr(0x26));
		expectedAddresses.add(addr(0x30), addr(0x30));
		expectedAddresses.add(addr(0x60), addr(0x60));
		expectedAddresses.add(addr(0x90), addr(0x90));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowBackOnlyConditionalCalls() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followConditionalCalls(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x0a), addr(0x0a));
		selectionSet.add(addr(0x0e), addr(0x0e));
		selectionSet.add(addr(0x0f), addr(0x0f));
		selectionSet.add(addr(0x26), addr(0x26));
		selectionSet.add(addr(0x30), addr(0x30));
		selectionSet.add(addr(0x60), addr(0x60));
		selectionSet.add(addr(0x90), addr(0x90));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0a), addr(0x0a));
		expectedAddresses.add(addr(0x0e), addr(0x20));
		expectedAddresses.add(addr(0x25), addr(0x26));
		expectedAddresses.add(addr(0x30), addr(0x30));
		expectedAddresses.add(addr(0x60), addr(0x60));
		expectedAddresses.add(addr(0x90), addr(0x90));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowBackOnlyComputedCalls() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followComputedCalls(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x0a), addr(0x0a));
		selectionSet.add(addr(0x0e), addr(0x0e));
		selectionSet.add(addr(0x0f), addr(0x0f));
		selectionSet.add(addr(0x26), addr(0x26));
		selectionSet.add(addr(0x30), addr(0x30));
		selectionSet.add(addr(0x60), addr(0x60));
		selectionSet.add(addr(0x90), addr(0x90));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0a), addr(0x0a));
		expectedAddresses.add(addr(0x0e), addr(0x0e));
		expectedAddresses.add(addr(0x0f), addr(0x0f));
		expectedAddresses.add(addr(0x25), addr(0x2c));
		expectedAddresses.add(addr(0x30), addr(0x30));
		expectedAddresses.add(addr(0x60), addr(0x60));
		expectedAddresses.add(addr(0x90), addr(0x90));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowBackOnlyUnconditionalJumps() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followUnconditionalJumps(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x0a), addr(0x0a));
		selectionSet.add(addr(0x0e), addr(0x0e));
		selectionSet.add(addr(0x0f), addr(0x0f));
		selectionSet.add(addr(0x26), addr(0x26));
		selectionSet.add(addr(0x30), addr(0x30));
		selectionSet.add(addr(0x60), addr(0x60));
		selectionSet.add(addr(0x90), addr(0x90));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x0f));
		expectedAddresses.add(addr(0x25), addr(0x26));
		expectedAddresses.add(addr(0x30), addr(0x30));
		expectedAddresses.add(addr(0x60), addr(0x60));
		expectedAddresses.add(addr(0x90), addr(0x90));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowBackOnlyConditionalJumps() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followConditionalJumps(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x0a), addr(0x0a));
		selectionSet.add(addr(0x0e), addr(0x0e));
		selectionSet.add(addr(0x0f), addr(0x0f));
		selectionSet.add(addr(0x26), addr(0x26));
		selectionSet.add(addr(0x30), addr(0x30));
		selectionSet.add(addr(0x60), addr(0x60));
		selectionSet.add(addr(0x90), addr(0x90));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x07));
		expectedAddresses.add(addr(0x0a), addr(0x0a));
		expectedAddresses.add(addr(0x0e), addr(0x0f));
		expectedAddresses.add(addr(0x25), addr(0x2e));
		expectedAddresses.add(addr(0x30), addr(0x30));
		expectedAddresses.add(addr(0x60), addr(0x60));
		expectedAddresses.add(addr(0x90), addr(0x90));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowBackOnlyComputedJumps() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followComputedJumps(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x0a), addr(0x0a));
		selectionSet.add(addr(0x0e), addr(0x0e));
		selectionSet.add(addr(0x0f), addr(0x0f));
		selectionSet.add(addr(0x26), addr(0x26));
		selectionSet.add(addr(0x30), addr(0x30));
		selectionSet.add(addr(0x60), addr(0x60));
		selectionSet.add(addr(0x90), addr(0x90));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0a), addr(0x0a));
		expectedAddresses.add(addr(0x0e), addr(0x26));
		expectedAddresses.add(addr(0x30), addr(0x30));
		expectedAddresses.add(addr(0x60), addr(0x60));
		expectedAddresses.add(addr(0x90), addr(0x90));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowBackOnlyPointers() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followPointers(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x0a), addr(0x0a));
		selectionSet.add(addr(0x0e), addr(0x0e));
		selectionSet.add(addr(0x0f), addr(0x0f));
		selectionSet.add(addr(0x26), addr(0x26));
		selectionSet.add(addr(0x30), addr(0x30));
		selectionSet.add(addr(0x60), addr(0x60));
		selectionSet.add(addr(0x90), addr(0x90));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0a), addr(0x0a));
		expectedAddresses.add(addr(0x0e), addr(0x0e));
		expectedAddresses.add(addr(0x0f), addr(0x0f));
		expectedAddresses.add(addr(0x25), addr(0x26));
		expectedAddresses.add(addr(0x30), addr(0x30));
		expectedAddresses.add(addr(0x60), addr(0x60));
		expectedAddresses.add(addr(0x90), addr(0x90));
		expectedAddresses.add(addr(0x5000), addr(0x5003));
		expectedAddresses.add(addr(0x5020), addr(0x502b));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowBackOnlyPointers2() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followPointers(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x231), addr(0x231));
		selectionSet.add(addr(0x331), addr(0x331));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x5008), addr(0x500b));
		expectedAddresses.add(addr(0x5040), addr(0x504b));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsToAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}
}
