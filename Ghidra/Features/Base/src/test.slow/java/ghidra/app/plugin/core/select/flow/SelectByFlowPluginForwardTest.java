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

public class SelectByFlowPluginForwardTest extends AbstractSelectByFlowPluginTest {

	@Test
	public void testFollowAllFlowsFrom0x0() {

		goTo(addr(0x0));

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x24));
		expectedAddresses.add(addr(0x26), addr(0x2f));
		expectedAddresses.add(addr(0x30), addr(0x52));
		expectedAddresses.add(addr(0x54), addr(0x5f));
		expectedAddresses.add(addr(0x60), addr(0x84));
		expectedAddresses.add(addr(0x86), addr(0x8f));
		expectedAddresses.add(addr(0x90), addr(0xb4));
		expectedAddresses.add(addr(0xb6), addr(0xbf));
		expectedAddresses.add(addr(0x130), addr(0x131));
		expectedAddresses.add(addr(0x160), addr(0x161));
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5034), addr(0x5037));
		expectedAddresses.add(addr(0x5040), addr(0x5040));
		// CodeBrowser expands selection to the code unit.
		expectedAddresses.add(addr(0x5030), addr(0x503b));
		expectedAddresses.add(addr(0x5040), addr(0x504b));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectAllFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowAllFlowsFrom0x17() {

		goTo(addr(0x17));

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x17), addr(0x24));
		expectedAddresses.add(addr(0x26), addr(0x2f));
		expectedAddresses.add(addr(0x60), addr(0x84));
		expectedAddresses.add(addr(0x86), addr(0x8f));
		expectedAddresses.add(addr(0x90), addr(0xb4));
		expectedAddresses.add(addr(0xb6), addr(0xbf));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5034), addr(0x5037));
		expectedAddresses.add(addr(0x5040), addr(0x5040));
		// CodeBrowser expands selection to the code unit.
		expectedAddresses.add(addr(0x5030), addr(0x503b));
		expectedAddresses.add(addr(0x5040), addr(0x504b));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectAllFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowAllFlowsFromSelection() {

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x06), addr(0x06));
		selectionSet.add(addr(0x0c), addr(0x0c));
		selectionSet.add(addr(0x11), addr(0x11));
		selectionSet.add(addr(0x1c), addr(0x1c));
		selectionSet.add(addr(0x23), addr(0x23));
		selectionSet.add(addr(0x28), addr(0x28));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x24));
		expectedAddresses.add(addr(0x26), addr(0x2f));
		expectedAddresses.add(addr(0x30), addr(0x52));
		expectedAddresses.add(addr(0x54), addr(0x5f));
		expectedAddresses.add(addr(0x60), addr(0x84));
		expectedAddresses.add(addr(0x86), addr(0x8f));
		expectedAddresses.add(addr(0x90), addr(0xb4));
		expectedAddresses.add(addr(0xb6), addr(0xbf));
		expectedAddresses.add(addr(0x130), addr(0x131));
		expectedAddresses.add(addr(0x160), addr(0x161));
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5034), addr(0x5037));
		expectedAddresses.add(addr(0x5040), addr(0x5040));
		// CodeBrowser expands selection to the code unit.
		expectedAddresses.add(addr(0x5030), addr(0x503b));
		expectedAddresses.add(addr(0x5040), addr(0x504b));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectAllFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowWithNoLimitedFlows() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOnAllFollowFlow(flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x06), addr(0x06));
		selectionSet.add(addr(0x0c), addr(0x0c));
		selectionSet.add(addr(0x11), addr(0x11));
		selectionSet.add(addr(0x1c), addr(0x1c));
		selectionSet.add(addr(0x23), addr(0x23));
		selectionSet.add(addr(0x28), addr(0x28));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x0), addr(0x24));
		expectedAddresses.add(addr(0x26), addr(0x2f));
		expectedAddresses.add(addr(0x30), addr(0x52));
		expectedAddresses.add(addr(0x54), addr(0x5f));
		expectedAddresses.add(addr(0x60), addr(0x84));
		expectedAddresses.add(addr(0x86), addr(0x8f));
		expectedAddresses.add(addr(0x90), addr(0xb4));
		expectedAddresses.add(addr(0xb6), addr(0xbf));
		expectedAddresses.add(addr(0x130), addr(0x131));
		expectedAddresses.add(addr(0x160), addr(0x161));
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x230), addr(0x231));
		expectedAddresses.add(addr(0x260), addr(0x261));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x330), addr(0x331));
		expectedAddresses.add(addr(0x360), addr(0x361));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5034), addr(0x5037));
		expectedAddresses.add(addr(0x5040), addr(0x5040));
		// CodeBrowser expands selection to the code unit.
		expectedAddresses.add(addr(0x5030), addr(0x503b));
		expectedAddresses.add(addr(0x5040), addr(0x504b));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowLimitingAllFlows() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x06), addr(0x06));
		selectionSet.add(addr(0x0c), addr(0x0c));
		selectionSet.add(addr(0x11), addr(0x11));
		selectionSet.add(addr(0x1c), addr(0x1c));
		selectionSet.add(addr(0x23), addr(0x23));
		selectionSet.add(addr(0x28), addr(0x28));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x06), addr(0x09));
		expectedAddresses.add(addr(0x0c), addr(0x0d));
		expectedAddresses.add(addr(0x11), addr(0x24));
		expectedAddresses.add(addr(0x28), addr(0x2f));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowOnlyUnconditionalCalls() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followUnconditionalCalls(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x06), addr(0x06));
		selectionSet.add(addr(0x0c), addr(0x0c));
		selectionSet.add(addr(0x11), addr(0x11));
		selectionSet.add(addr(0x1c), addr(0x1c));
		selectionSet.add(addr(0x23), addr(0x23));
		selectionSet.add(addr(0x28), addr(0x28));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x06), addr(0x09));
		expectedAddresses.add(addr(0x0c), addr(0x0d));
		expectedAddresses.add(addr(0x11), addr(0x24));
		expectedAddresses.add(addr(0x28), addr(0x39));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowOnlyConditionalCalls() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followConditionalCalls(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x06), addr(0x06));
		selectionSet.add(addr(0x0c), addr(0x0c));
		selectionSet.add(addr(0x11), addr(0x11));
		selectionSet.add(addr(0x1c), addr(0x1c));
		selectionSet.add(addr(0x23), addr(0x23));
		selectionSet.add(addr(0x28), addr(0x28));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x06), addr(0x09));
		expectedAddresses.add(addr(0x0c), addr(0x0d));
		expectedAddresses.add(addr(0x11), addr(0x24));
		expectedAddresses.add(addr(0x28), addr(0x2f));
		expectedAddresses.add(addr(0x60), addr(0x69));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowOnlyComputedCalls() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followComputedCalls(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x06), addr(0x06));
		selectionSet.add(addr(0x0c), addr(0x0c));
		selectionSet.add(addr(0x11), addr(0x11));
		selectionSet.add(addr(0x1c), addr(0x1c));
		selectionSet.add(addr(0x23), addr(0x23));
		selectionSet.add(addr(0x28), addr(0x28));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x06), addr(0x09));
		expectedAddresses.add(addr(0x0c), addr(0x0d));
		expectedAddresses.add(addr(0x11), addr(0x24));
		expectedAddresses.add(addr(0x28), addr(0x2f));
		expectedAddresses.add(addr(0x90), addr(0x99));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowOnlyUnconditionalJumps() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followUnconditionalJumps(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x06), addr(0x06));
		selectionSet.add(addr(0x0c), addr(0x0c));
		selectionSet.add(addr(0x11), addr(0x11));
		selectionSet.add(addr(0x1c), addr(0x1c));
		selectionSet.add(addr(0x23), addr(0x23));
		selectionSet.add(addr(0x28), addr(0x28));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x06), addr(0x09));
		expectedAddresses.add(addr(0x0c), addr(0x0d));
		expectedAddresses.add(addr(0x0e), addr(0x24));
		expectedAddresses.add(addr(0x28), addr(0x2f));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowOnlyConditionalJumps() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followConditionalJumps(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x06), addr(0x06));
		selectionSet.add(addr(0x0c), addr(0x0c));
		selectionSet.add(addr(0x11), addr(0x11));
		selectionSet.add(addr(0x1c), addr(0x1c));
		selectionSet.add(addr(0x23), addr(0x23));
		selectionSet.add(addr(0x28), addr(0x28));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x06), addr(0x0d));
		expectedAddresses.add(addr(0x11), addr(0x24));
		expectedAddresses.add(addr(0x26), addr(0x2f));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowOnlyComputedJumps() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followComputedJumps(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x06), addr(0x06));
		selectionSet.add(addr(0x0c), addr(0x0c));
		selectionSet.add(addr(0x11), addr(0x11));
		selectionSet.add(addr(0x1c), addr(0x1c));
		selectionSet.add(addr(0x23), addr(0x23));
		selectionSet.add(addr(0x28), addr(0x28));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x06), addr(0x09));
		expectedAddresses.add(addr(0x0c), addr(0x0d));
		expectedAddresses.add(addr(0x11), addr(0x24));
		expectedAddresses.add(addr(0x26), addr(0x2f));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowOnlyPointers() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followPointers(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x06), addr(0x06));
		selectionSet.add(addr(0x0c), addr(0x0c));
		selectionSet.add(addr(0x11), addr(0x11));
		selectionSet.add(addr(0x1c), addr(0x1c));
		selectionSet.add(addr(0x23), addr(0x23));
		selectionSet.add(addr(0x28), addr(0x28));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x06), addr(0x09));
		expectedAddresses.add(addr(0x0c), addr(0x0d));
		expectedAddresses.add(addr(0x11), addr(0x24));
		expectedAddresses.add(addr(0x28), addr(0x2f));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowOnlyPointers2() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);
		followPointers(true, flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x190), addr(0x190));
		selectionSet.add(addr(0x290), addr(0x290));
		selectionSet.add(addr(0x390), addr(0x390));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5034), addr(0x5037));
		expectedAddresses.add(addr(0x5040), addr(0x504b));
		// CodeBrowser expands selection to the code unit.
		expectedAddresses.add(addr(0x5030), addr(0x503b));
		expectedAddresses.add(addr(0x5040), addr(0x504b));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testDoNotFollowPointers() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x190), addr(0x190));
		selectionSet.add(addr(0x290), addr(0x290));
		selectionSet.add(addr(0x390), addr(0x390));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x390), addr(0x391));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectLimitedFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}

	@Test
	public void testFollowPointersWhenFollowingAll() {

		ToolOptions flowOptions = tool.getOptions(GhidraOptions.CATEGORY_FLOW_OPTIONS);
		turnOffAllFollowFlow(flowOptions);

		AddressSet selectionSet = new AddressSet();
		selectionSet.add(addr(0x190), addr(0x190));
		selectionSet.add(addr(0x290), addr(0x290));
		selectionSet.add(addr(0x390), addr(0x390));
		setSelection(selectionSet);

		AddressSet expectedAddresses = new AddressSet();
		expectedAddresses.add(addr(0x190), addr(0x191));
		expectedAddresses.add(addr(0x290), addr(0x291));
		expectedAddresses.add(addr(0x390), addr(0x391));
		expectedAddresses.add(addr(0x5034), addr(0x5037));
		expectedAddresses.add(addr(0x5040), addr(0x5040));
		// CodeBrowser expands selection to the code unit.
		expectedAddresses.add(addr(0x5030), addr(0x503b));
		expectedAddresses.add(addr(0x5040), addr(0x504b));
		ProgramSelection expectedSelection = new ProgramSelection(expectedAddresses);

		performAction(selectAllFlowsFromAction, getActionContext(), true);

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();

		assertEquals(new MySelection(expectedSelection), new MySelection(currentSelection));
	}
}
