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

import java.awt.Dimension;
import java.awt.Window;

import org.junit.Test;

import docking.ComponentProvider;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.graph.export.GraphExporterDialog;
import ghidra.graph.visualization.DefaultGraphDisplay;
import ghidra.graph.visualization.DefaultGraphDisplayComponentProvider;
import ghidra.service.graph.*;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

public class GraphServicesScreenShots extends GhidraScreenShotGenerator {

	public GraphServicesScreenShots() {
		super();
	}

	@Override
	public void setUp() throws Exception {
		super.setUp();
		setUser("User");
	}

	@Test
	public void testExportDialog() throws Exception {
		GraphDisplayBroker broker = tool.getService(GraphDisplayBroker.class);
		GraphDisplayProvider export = broker.getGraphDisplayProvider("Graph Export");
		GraphDisplay display = export.getGraphDisplay(false, TaskMonitor.DUMMY);
		AttributedGraph graph = new AttributedGraph();
		display.setGraph(graph, "test", false, TaskMonitor.DUMMY);
		GraphExporterDialog dialog = (GraphExporterDialog) getDialog();
		dialog.setFilePath("/users/user1/graph");
		captureDialog();
	}

	@Test
	public void testDefaultGraphDisplay() throws Exception {

		GraphDisplayBroker broker = tool.getService(GraphDisplayBroker.class);
		GraphDisplayProvider export = broker.getGraphDisplayProvider("Default Graph Display");
		GraphDisplay display = export.getGraphDisplay(false, TaskMonitor.DUMMY);
		AttributedGraph graph = new AttributedGraph();
		AttributedVertex v1 = graph.addVertex("0000", "main");
		v1.setAttribute("VertexType", "Entry");
		AttributedVertex v2 = graph.addVertex("0100", "Fun_One");
		v2.setAttribute("VertexType", "Entry");
		AttributedVertex v3 = graph.addVertex("0200", "Fun_Two");
		v3.setAttribute("VertexType", "Entry");

		AttributedEdge e1 = graph.addEdge(v1, v2);
		e1.setAttribute("EdgeType", "Unconditional-Call");
		AttributedEdge e2 = graph.addEdge(v1, v3);
		e2.setAttribute("EdgeType", "Unconditional-Call");

		display.setGraph(graph, "Program Graph", false, TaskMonitor.DUMMY);
		waitForSwing();
		setGraphWindowSize(700, 500);
		runSwing(() -> ((DefaultGraphDisplay) display).centerAndScale());
		waitForSwing();

		captureProvider(DefaultGraphDisplayComponentProvider.class);
	}

	private void setGraphWindowSize(int width, int height) {
		ComponentProvider provider = tool.getWindowManager()
				.getComponentProvider(DefaultGraphDisplayComponentProvider.class);
		runSwing(() -> {
			Window window = tool.getWindowManager().getProviderWindow(provider);
			if (window == null) {
				throw new AssertException("Could not find window for " +
					"provider--is it showing?: " + provider.getName());
			}

			window.setSize(new Dimension(width, height));
			window.toFront();
			provider.getComponent().requestFocus();
			paintFix(window);
		});
		waitForSwing();
	}

}
