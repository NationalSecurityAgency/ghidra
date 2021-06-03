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
package ghidra.graph;

import static org.junit.Assert.*;

import javax.swing.JComponent;
import javax.swing.JPanel;

import org.junit.Test;

import docking.*;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import ghidra.graph.graphs.*;
import ghidra.graph.support.TestVisualGraph;
import ghidra.graph.support.TextAreaTestVertex;
import ghidra.graph.viewer.AbstractVisualGraphTest;
import ghidra.graph.viewer.VisualGraphView;

public class VisualGraphComponentProviderTest extends AbstractVisualGraphTest {

	private VisualGraphComponentProvider<AbstractTestVertex, TestEdge, TestVisualGraph> provider;
	private VisualGraphView<AbstractTestVertex, TestEdge, TestVisualGraph> viewer;

	@Override
	public void setUp() throws Exception {

		FakeDockingTool tool = createTool();
		DockingWindowManager dwm = tool.getWindowManager();
		runSwing(() -> dwm.setVisible(true), false);

		buildAndLayoutGraph();

		viewer = new VisualGraphView<>();
		viewer.setGraph(graph);

		provider = new TestProvider(tool);
		provider.setVisible(true);
	}

	@Override
	public void tearDown() {
		closeAllWindows();
	}

	@Override
	protected TestVisualGraph buildGraph() {

		TestVisualGraph g = new TestVisualGraph();

		AbstractTestVertex v1 = new LabelTestVertex("1");
		AbstractTestVertex v2 = new LabelTestVertex("2");
		AbstractTestVertex v3 = new LabelTestVertex("3");
		TextAreaTestVertex textAreaVertex = new TextAreaTestVertex("Text Area vertex...");
		TestEdge e1 = new TestEdge(v1, v2);
		TestEdge e2 = new TestEdge(v2, v3);
		TestEdge e3 = new TestEdge(v1, textAreaVertex);

		g.addVertex(v1);
		g.addVertex(v2);
		g.addVertex(v3);
		g.addVertex(textAreaVertex);
		g.addEdge(e1);
		g.addEdge(e2);
		g.addEdge(e3);

		return g;
	}

	@Test
	public void testOpenSatelliteWindowReopensWhenMainGraphWindowIsReopened() {

		//
		// If the user closes the main graph provider while the satellite is undocked and showing,
		// then verify the satellite window will re-open when the main graph provider is re-opened
		//

		assertTrue(provider.isSatelliteShowing());
		assertTrue(provider.isSatelliteDocked());

		setSatelliteDocked(false);
		assertTrue(provider.isSatelliteShowing());
		assertFalse(provider.isSatelliteDocked());
		assertUndockedProviderVisible();

		closeMainGraphProvider();
		assertUndockedProviderHidden();

		showMainGraphProvider();
		assertUndockedProviderVisible();
		assertTrue(provider.isSatelliteShowing());
	}

	@Test
	public void testClosedSatelliteWindowDoesNotReopenWhenMainGraphWindowIsReopened() {

		//
		// If the user closes an undocked satellite window, then closes and re-opens the 
		// main graph provider, the satellite window should *not* re-open.
		//

		assertTrue(provider.isSatelliteShowing());
		assertTrue(provider.isSatelliteDocked());

		setSatelliteDocked(false);
		assertTrue(provider.isSatelliteShowing());
		assertFalse(provider.isSatelliteDocked());
		assertUndockedProviderVisible();

		setSatelliteVisible(false);
		assertFalse(provider.isSatelliteShowing());
		assertFalse(provider.isSatelliteDocked());

		closeMainGraphProvider();
		assertUndockedProviderHidden();

		showMainGraphProvider();
		assertUndockedProviderHidden();
		assertFalse(provider.isSatelliteShowing());
		assertFalse(provider.isSatelliteDocked());
	}

	@Test
	public void testHideUndockedSatellite_ByClosingSatelliteProvider() {

		//
		// If the user closes the satellite window, verify that can re-open it via the action
		//

		assertTrue(provider.isSatelliteShowing());
		assertTrue(provider.isSatelliteDocked());

		setSatelliteDocked(false);
		assertTrue(provider.isSatelliteShowing());
		assertFalse(provider.isSatelliteDocked());
		assertUndockedProviderVisible();

		setSatelliteVisible(false);
		assertFalse(provider.isSatelliteShowing());
		assertFalse(provider.isSatelliteDocked());

		setSatelliteVisible(true);
		assertTrue(provider.isSatelliteShowing());
		assertFalse(provider.isSatelliteDocked());
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertUndockedProviderHidden() {
		ComponentProvider p = provider.getSatelliteProvider();
		if (p == null) {
			return;
		}
		assertFalse("Undocked provider is not hidden", p.isVisible());
	}

	private void assertUndockedProviderVisible() {
		ComponentProvider p = provider.getSatelliteProvider();
		assertNotNull("Undocked provider does not exist", p);
		assertTrue("Undocked provider is not visible", p.isVisible());
	}

	private void showMainGraphProvider() {
		runSwing(() -> provider.setVisible(true));
	}

	private void closeMainGraphProvider() {
		runSwing(() -> provider.closeComponent());
	}

	private void setSatelliteVisible(boolean visible) {
		Tool tool = provider.getTool();
		String name = "Display Satellite View";
		DockingActionIf action = getAction(tool, name);
		assertNotNull(name + " not in tool", action);
		ToggleDockingAction showSatelliteAction = (ToggleDockingAction) action;
		setToggleActionSelected(showSatelliteAction, provider.getActionContext(null), visible);
		waitForSwing();
	}

	private void setSatelliteDocked(boolean docked) {
		Tool tool = provider.getTool();
		String name = "Dock Satellite View";
		DockingActionIf action = getAction(tool, name);
		assertNotNull(name + " not in tool", action);
		ToggleDockingAction dockSatelliteAction = (ToggleDockingAction) action;
		setToggleActionSelected(dockSatelliteAction, provider.getActionContext(null), docked);
		waitForSwing();
	}

	private FakeDockingTool createTool() {
		return runSwing(() -> new FakeDockingTool());
	}
//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TestProvider
			extends VisualGraphComponentProvider<AbstractTestVertex, TestEdge, TestVisualGraph> {

		private JComponent component;

		protected TestProvider(Tool tool) {
			super(tool, "Test VG Provider", "Test Owner");

			component = new JPanel();
			component.add(viewer.getViewComponent());

			addToTool();
			addSatelliteFeature();
		}

		@Override
		public VisualGraphView<AbstractTestVertex, TestEdge, TestVisualGraph> getView() {
			return viewer;
		}

		@Override
		public JComponent getComponent() {
			return component;
		}

	}
}
