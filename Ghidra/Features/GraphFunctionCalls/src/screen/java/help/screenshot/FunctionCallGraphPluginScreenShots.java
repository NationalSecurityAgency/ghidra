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

import javax.swing.SwingUtilities;

import org.junit.*;

import docking.DockableComponent;
import edu.uci.ics.jung.visualization.picking.PickedState;
import functioncalls.graph.*;
import functioncalls.graph.view.FcgView;
import functioncalls.plugin.*;
import generic.test.TestUtils;
import ghidra.graph.viewer.*;
import ghidra.program.model.address.TestAddress;
import ghidra.program.model.listing.Function;

public class FunctionCallGraphPluginScreenShots extends GhidraScreenShotGenerator {

	private FcgProvider provider;

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		FunctionCallGraphPlugin plugin = env.addPlugin(FunctionCallGraphPlugin.class);
		provider = new FcgProvider(tool, plugin);
		provider.setVisible(true);

		setTestFunctionInProvider();
	}

	@Override
	public void dockingSetUp() {
		// We get an error dialog about default tools, since this test is not in the
		// Integration Test project.  Disable the error dialogs.
		setErrorGUIEnabled(false);
	}

	@Override
	@After
	public void tearDown() throws Exception {
		tool.showComponentProvider(provider, false);
		super.tearDown();
	}

	@Test
	public void testFunctionCallGraphProvider() {

		Window w = moveProviderToItsOwnWindow(provider, 700, 500);
		centerGraph();
		captureWindow(w);
	}

	@Test
	public void testTooManyReferences() {

		FcgFunction source = new FcgFunction("FUN_1234", new TestAddress(1));

		createManyOutgoingReferences(source, FcgProvider.MAX_REFERENCES + 1);

		setFunction(source);

		FcgVertex v = graph().getVertex(source);
		clearSelection();
		runSwing(() -> v.setHovered(true));

		captureProvider(provider);
		captureNode(v);
	}

	private void clearSelection() {
		GraphViewer<FcgVertex, FcgEdge> viewer = viewer();
		PickedState<FcgVertex> picker = viewer.getPickedVertexState();
		runSwing(() -> {
			picker.clear();
		});
	}

	private GraphViewer<FcgVertex, FcgEdge> viewer() {
		FcgView view = provider.getView();
		return view.getPrimaryGraphViewer();
	}

	private void captureNode(FcgVertex v) {
		FcgView view = provider.getView();
		GraphViewer<FcgVertex, FcgEdge> viewer = view.getPrimaryGraphViewer();
		Rectangle bounds = GraphViewerUtils.getVertexBoundsInViewSpace(viewer, v);

		DockableComponent dockableComponent = getDockableComponent(viewer);
		Point loc = SwingUtilities.convertPoint(viewer, bounds.getLocation(), dockableComponent);
		bounds.setLocation(loc);

		Rectangle area = new Rectangle(bounds);
		int offset = 10;
		area.x -= offset;
		area.y -= offset;
		area.width += (2 * offset);
		area.height += (2 * offset);

		// drawRectangle(Color.ORANGE, area, 5);

		crop(area);
	}

	private FunctionCallGraph graph() {
		return (FunctionCallGraph) invokeInstanceMethod("getGraph", provider);
	}

	private void createManyOutgoingReferences(FcgFunction f, int n) {
		int counter = 10;
		for (int i = 0; i < n; i++) {
			FcgFunction newF =
				new FcgFunction("Many_Outgoing_Function_" + (i + 1), new TestAddress(counter++));
			f.addCalledFunction(newF);
		}
	}

	private void setTestFunctionInProvider() {
		int counter = 0;

		FcgFunction f = new FcgFunction("Source_Function", new TestAddress(counter++));

		FcgFunction in = new FcgFunction("FUN_IN_1", new TestAddress(counter++));
		in.addCalledFunction(f);
		f.addCallerFunction(in);

		in = new FcgFunction("FUN_IN_2", new TestAddress(counter++));
		in.addCalledFunction(f);
		f.addCallerFunction(in);

		for (int i = 1; i < 5; i++) {
			String name = "FUN_OUT_" + i;
			FcgFunction out = new FcgFunction(name, new TestAddress(counter++));
			out.addCallerFunction(f);
			f.addCalledFunction(out);
		}

		setFunction(f);
	}

	private void setFunction(FcgFunction f) {
		runSwing(() -> {
			TestUtils.invokeInstanceMethod("setFunction", provider, Function.class, f);
		});
	}

	private void centerGraph() {

		waitForGraph();

		VisualGraphViewUpdater<FcgVertex, FcgEdge> updater = getGraphUpdater();
		updater.fitGraphToViewerNow();
		waitForGraph();
	}

	private VisualGraphViewUpdater<FcgVertex, FcgEdge> getGraphUpdater() {
		@SuppressWarnings("unchecked")
		VisualGraphView<FcgVertex, FcgEdge, FunctionCallGraph> view =
			(VisualGraphView<FcgVertex, FcgEdge, FunctionCallGraph>) getInstanceField("view",
				provider);

		GraphViewer<FcgVertex, FcgEdge> primaryViewer = view.getPrimaryGraphViewer();
		VisualGraphViewUpdater<FcgVertex, FcgEdge> updater = primaryViewer.getViewUpdater();
		return updater;
	}

	private void waitForGraph() {
		VisualGraphViewUpdater<FcgVertex, FcgEdge> updater = getGraphUpdater();
		waitForCondition(() -> !updater.isBusy());
		waitForSwing();
	}
}
