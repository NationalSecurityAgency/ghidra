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
package help.screenshot;

import java.awt.*;
import java.awt.geom.Point2D;

import org.junit.Before;
import org.junit.Test;

import datagraph.DataGraphProvider;
import datagraph.data.graph.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.features.base.replace.SearchAndReplacePlugin;
import ghidra.graph.viewer.GraphComponent;
import ghidra.graph.viewer.options.VisualGraphOptions;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.AssertException;

/**
 * Screenshots for help/topics/DataGraphPlugin/Data_Graph.html
 */
public class DataGraphPluginScreenShots extends AbstractSearchScreenShots {

	private CodeBrowserPlugin cb;
	private SearchAndReplacePlugin plugin;

	@Override
	protected String getHelpTopicName() {
		return "DataGraphPlugin";
	}

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		plugin = env.getPlugin(SearchAndReplacePlugin.class);
		cb = env.getPlugin(CodeBrowserPlugin.class);

		program.withTransaction("screen shot", () -> {
			ReferenceManager refMgr = program.getReferenceManager();
			refMgr.addMemoryReference(addr(0x040011c), addr(0x0400000), RefType.DATA,
				SourceType.ANALYSIS, 0);
		});

		env.showTool();
	}

	@Test
	public void testDataGraph() {
		go(0x4000e8);
		performAction("Display Data Graph", "DataGraphPlugin", true);

		DataGraphProvider provider = getProvider(DataGraphProvider.class);
		DegController controller = provider.getController();
		DataExplorationGraph graph = controller.getGraph();
		DataDegVertex root = (DataDegVertex) graph.getRoot();
		turnOffAnimation(controller);

		expandRow(root, 3);
		openPointer(root, 13);
		setSize(provider, 850, 550);
		moveGraph(controller, -200, -280);

		waitForSwing();
		captureProvider(DataGraphProvider.class);

	}

	@Test
	public void testCodeVertex() {
		go(0x40b1f4);
		performAction("Display Data Graph", "DataGraphPlugin", true);

		DataGraphProvider provider = getProvider(DataGraphProvider.class);
		DegController controller = provider.getController();
		turnOffAnimation(controller);

		performAction("Incoming References", "DataGraphPlugin", provider, true);

		setSize(provider, 600, 400);
		moveGraph(controller, -100, -350);

		waitForSwing();
		captureProvider(DataGraphProvider.class);

	}

	private void moveGraph(DegController controller, int deltaX, int deltaY) {
		runSwing(() -> {
			DegVertex root = controller.getGraph().getRoot();
			Point2D location = root.getLocation();
			controller.centerPoint(
				new Point((int) location.getX() + deltaX, (int) location.getY() + deltaY));
		});
	}

	private void openPointer(DataDegVertex root, int rowIndex) {
		runSwing(() -> {
			root.openPointerReference(rowIndex);
		});
	}

	private void expandRow(DataDegVertex root, int rowIndex) {
		runSwing(() -> {
			root.expand(rowIndex);
		});
	}

	private void turnOffAnimation(DegController controller) {
		runSwing(() -> {
			GraphComponent<DegVertex, DegEdge, DataExplorationGraph> comp =
				controller.getView().getGraphComponent();
			VisualGraphOptions graphOptions = comp.getGraphOptions();
			graphOptions.setUseAnimation(false);
		});
	}

	private void setSize(DataGraphProvider provider, int width, int height) {
		runSwing(() -> {
			Window window = tool.getWindowManager().getProviderWindow(provider);
			if (window == null) {
				throw new AssertException("Could not find window for " +
					"provider--is it showing?: " + provider.getName());
			}

			window.setSize(new Dimension(width, height));
		});
	}
}
