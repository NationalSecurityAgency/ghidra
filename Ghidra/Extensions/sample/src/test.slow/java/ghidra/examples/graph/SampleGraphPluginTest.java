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
package ghidra.examples.graph;

import static org.junit.Assert.*;

import java.awt.Component;
import java.util.Collection;
import java.util.List;

import javax.swing.JTextField;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.viewer.VisualGraphViewUpdater;
import ghidra.graph.viewer.layout.LayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * An integration test for the {@link SampleGraphPlugin}.   These tests are really just
 * regression tests meant to catch if the sample plugin gets broken.  The functionality of
 * the plugin is barely tested.
 */
public class SampleGraphPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private SampleGraphPlugin plugin;
	private SampleGraphProvider provider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		PluginTool tool = env.launchDefaultTool();
		plugin = env.addPlugin(SampleGraphPlugin.class);
		DockingActionIf showProviderAction =
			getAction(plugin, SampleGraphPlugin.SHOW_PROVIDER_ACTION_NAME);
		performAction(showProviderAction, true);
		provider = (SampleGraphProvider) tool.getComponentProvider(SampleGraphProvider.NAME);
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testGraphGetsDisplayed() {

		// just make sure vertices were created
		assertTrue(provider.getGraph().getVertexCount() > 10);
	}

	@Test
	public void testChangeLayoutAction() {

		VisualGraphLayout<SampleVertex, SampleEdge> lastLayout = getCurrentLayout();

		setNewLayout("Circle Layout");

		assertNotSame(lastLayout, getCurrentLayout());
	}

	@Test
	public void testFilter() {

		showFilter();

		enterFilterText("Sample");

		// note: we are not testing the actual filter correctness, as there is already a unit
		//       test covering that functionality.
		assertSomeVerticesFilteredOut();
		assertSomeVerticesMatchFilter();
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertSomeVerticesFilteredOut() {

		SampleGraph graph = provider.getGraph();
		Collection<SampleVertex> vertices = graph.getVertices();
		boolean hasFiltered = vertices.stream().anyMatch(v -> v.getAlpha() < 1D);
		assertTrue(hasFiltered);
	}

	private void assertSomeVerticesMatchFilter() {

		SampleGraph graph = provider.getGraph();
		Collection<SampleVertex> vertices = graph.getVertices();
		boolean hasMatches = vertices.stream().anyMatch(v -> Double.compare(v.getAlpha(), 1D) == 0);
		assertTrue(hasMatches);
	}

	private void showFilter() {

		ToggleDockingAction showFilterAction =
			(ToggleDockingAction) getAction(plugin, SampleGraphProvider.SHOW_FILTER_ACTION_NAME);
		setToggleActionSelected(showFilterAction, provider.getActionContext(null), true);

		Component filterPanel =
			findComponentByName(provider.getComponent(), "sample.graph.filter.panel");
		assertNotNull(filterPanel);
		assertTrue(filterPanel.isShowing());
	}

	private void enterFilterText(String text) {

		JTextField textField = findComponent(provider.getComponent(), JTextField.class);
		setText(textField, text);
		waitForSwing();
		waitForBusyGraph();
	}

	private void waitForBusyGraph() {

		VisualGraphViewUpdater<?, ?> updater = provider.getGraphViewUpdater();
		waitForCondition(() -> !updater.isBusy());
	}

	private VisualGraphLayout<SampleVertex, SampleEdge> getCurrentLayout() {

		SampleGraph graph = provider.getGraph();
		VisualGraphLayout<SampleVertex, SampleEdge> layout = graph.getLayout();
		return layout;
	}

	private void setNewLayout(String layoutName) {

		/*
		 	Note: we use LayoutProvider<?, ?, ?> here instead of 
		 	      LayoutProvider<SampleVertex, SampleEdge, SampleGraph> simply because
		 	      the former is more concise
		 */

		@SuppressWarnings("unchecked")
		MultiStateDockingAction<LayoutProvider<?, ?, ?>> relayoutAction =
			(MultiStateDockingAction<LayoutProvider<?, ?, ?>>) getAction(plugin,
				SampleGraphProvider.RELAYOUT_GRAPH_ACTION_NAME);

		// sanity check
		ActionState<LayoutProvider<?, ?, ?>> currentChoice = relayoutAction.getCurrentState();
		if (layoutName.equals(currentChoice.getUserData().getLayoutName())) {
			fail("Layout already selected--pick a new layout '" + layoutName + "'");
		}

		ActionState<LayoutProvider<?, ?, ?>> desiredChoice = null;
		List<ActionState<LayoutProvider<?, ?, ?>>> choices = relayoutAction.getAllActionStates();
		for (ActionState<LayoutProvider<?, ?, ?>> choice : choices) {

			LayoutProvider<?, ?, ?> layoutProvider = choice.getUserData();
			if (layoutName.equals(layoutProvider.getLayoutName())) {
				desiredChoice = choice;
				break;
			}
		}

		assertNotNull("Could not find layout '" + layoutName + "'", desiredChoice);

		ActionState<LayoutProvider<?, ?, ?>> theChoice = desiredChoice;
		runSwing(() -> relayoutAction.setCurrentActionState(theChoice));
	}

}
