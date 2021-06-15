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
package ghidra.app.plugin.core.debug.gui.target;

import static ghidra.app.plugin.core.debug.gui.target.DebuggerTargetsProviderFriend.selectNodeForObject;
import static org.junit.Assert.*;

import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.service.model.DebuggerConnectDialog;
import ghidra.dbg.model.TestDebuggerObjectModel;

/**
 * Tests of the target provider
 */
public class DebuggerTargetsProviderTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected DebuggerTargetsPlugin targetsPlugin;
	protected DebuggerTargetsProvider targetsProvider;

	@Before
	public void setUpTargetsProviderTest() throws Exception {
		targetsPlugin = addPlugin(tool, DebuggerTargetsPlugin.class);
		targetsProvider = waitForComponentProvider(DebuggerTargetsProvider.class);
	}

	@Test
	public void testConnectActionShowDialog() {
		modelServiceInternal.setModelFactories(List.of(mb.testFactory));
		waitForSwing();

		performAction(targetsProvider.actionConnect, false);
		DebuggerConnectDialog dialog = waitForDialogComponent(DebuggerConnectDialog.class);

		pressButtonByText(dialog, "Cancel", true);
	}

	@Test
	public void testRegisteredModelsShowInTree() throws Exception {
		createTestModel();
		waitForSwing();

		GTreeNode root = targetsProvider.tree.getModelRoot();
		assertEquals(targetsProvider.rootNode, root);

		List<GTreeNode> modelNodes = root.getChildren();
		assertEquals(1, modelNodes.size());

		GTreeNode nodeForTestModel = modelNodes.get(0);
		assertEquals(DebuggerModelNode.class, nodeForTestModel.getClass());

		DebuggerModelNode node = (DebuggerModelNode) nodeForTestModel;
		assertEquals(mb.testModel, node.getDebuggerModel());
		assertEquals(TestDebuggerObjectModel.TEST_MODEL_STRING, node.getDisplayText());
	}

	@Test
	public void testActionConnect() {
		assertTrue(targetsProvider.actionConnect.isEnabled());

		performAction(targetsProvider.actionConnect, false);
		waitForDialogComponent(DebuggerConnectDialog.class).close();
	}

	@Test
	public void testActionDisconnect() throws Exception {
		assertFalse(targetsProvider.actionDisconnect.isEnabled());

		createTestModel();
		waitForSwing();
		assertFalse(targetsProvider.actionDisconnect.isEnabled());

		selectNodeForObject(targetsProvider, mb.testModel);
		waitForSwing();
		assertTrue(targetsProvider.actionDisconnect.isEnabled());

		performAction(targetsProvider.actionDisconnect, true);
		waitForSwing();
		assertNull(targetsProvider.rootNode.findNodeForObject(mb.testModel));
	}

	@Test
	public void testActionFlushCaches() throws Exception {
		createTestModel();
		TestDebuggerObjectModel secondModel = new TestDebuggerObjectModel();
		modelService.addModel(secondModel);
		waitForSwing();

		selectNodeForObject(targetsProvider, mb.testModel);
		waitForSwing();
		performAction(targetsProvider.actionFlushCaches, false);
		waitForSwing();
		assertEquals(1, mb.testModel.clearInvalidateCachesCount());
		assertEquals(0, secondModel.clearInvalidateCachesCount());
	}

	protected static final Set<String> POPUP_ACTIONS = Set.of(
		AbstractConnectAction.NAME,
		AbstractDisconnectAction.NAME,
		AbstractFlushCachesAction.NAME);

	@Test
	public void testPopupActionsOnDebuggerModel() throws Exception {
		createTestModel();
		waitForSwing();

		clickTreeNode(targetsProvider.tree,
			targetsProvider.rootNode.findNodeForObject(mb.testModel), MouseEvent.BUTTON3);
		waitForSwing();
		assertMenu(POPUP_ACTIONS, Set.of(
			AbstractDisconnectAction.NAME,
			AbstractFlushCachesAction.NAME));
	}

	@Test
	public void testModelActivationOnClick() throws Exception {
		createTestModel();
		TestDebuggerObjectModel secondModel = new TestDebuggerObjectModel();
		modelService.addModel(secondModel);
		waitForSwing();

		// NB. Expansion is run in background task
		waitForPass(noExc(() -> {
			clickTreeNode(targetsProvider.tree,
				targetsProvider.rootNode.findNodeForObject(mb.testModel), MouseEvent.BUTTON1);
			waitForSwing();
			assertEquals(mb.testModel, modelService.getCurrentModel());
		}));

		waitForPass(noExc(() -> {
			clickTreeNode(targetsProvider.tree,
				targetsProvider.rootNode.findNodeForObject(secondModel), MouseEvent.BUTTON1);
			waitForSwing();
			assertEquals(secondModel, modelService.getCurrentModel());
		}));
	}

	@Test
	public void testActivateModelChangesSelection() throws Exception {
		createTestModel();
		TestDebuggerObjectModel secondModel = new TestDebuggerObjectModel();
		modelService.addModel(secondModel);
		waitForSwing();

		modelService.activateModel(mb.testModel);
		waitForSwing();
		DebuggerModelNode node1 =
			(DebuggerModelNode) targetsProvider.tree.getSelectionPath().getLastPathComponent();
		assertEquals(mb.testModel, node1.getDebuggerModel());

		modelService.activateModel(secondModel);
		waitForSwing();
		DebuggerModelNode node2 =
			(DebuggerModelNode) targetsProvider.tree.getSelectionPath().getLastPathComponent();
		assertEquals(secondModel, node2.getDebuggerModel());
	}
}
