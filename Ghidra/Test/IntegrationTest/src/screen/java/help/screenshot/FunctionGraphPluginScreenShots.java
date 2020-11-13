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

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.geom.Point2D;
import java.awt.geom.Point2D.Double;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;

import docking.*;
import docking.action.DockingAction;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.util.image.Callout;
import docking.util.image.CalloutComponentInfo;
import docking.widgets.dialogs.MultiLineInputDialog;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.VisualizationServer;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import generic.test.TestUtils;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.plugin.core.functiongraph.AbstractFunctionGraphTest;
import ghidra.app.plugin.core.functiongraph.FGProvider;
import ghidra.app.plugin.core.functiongraph.graph.*;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FGView;
import ghidra.graph.viewer.GraphViewerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

public class FunctionGraphPluginScreenShots extends AbstractFunctionGraphTest {

	private MyScreen screen;
	private int width = 400;
	private int height = 400;

	public FunctionGraphPluginScreenShots() {
		super();
	}

	@Override
	@Before
	public void setUp() throws Exception {

		screen = new MyScreen();
		try {
			screen.setUp();
		}
		catch (Exception e) {
			failWithException("Unepected exception in setup", e);
		}

		super.setUp();

		screen.program = program;

		setLayout();
	}

	@Override
	@After
	public void tearDown() throws Exception {
		// We share the program--don't let the screen release it's copy
		// screen.env.release(screen.program);

		super.tearDown();

		screen.saveOrDisplayImage(testName.getMethodName());
	}

	@Override
	protected TestEnv getEnv() {
		return screen.env;
	}

	@Override
	protected String getStartingProgramName() {
		return "WinHelloCPP.exe";
	}

	@Override
	protected void openProgram() {
		program = env.getProgram(getStartingProgramName());
	}

	@Override
	protected String getStartingAddress() {
		return "406630";
	}

	@Test
	public void testFunctionGraphWindow() {
		go("406630");// _strlen function

		setSize(750, 560);// size first, as the positioning is sensitive to the size
		setZoom(1.0);// full zoom
		centerDisplay();
		captureProviderWindow();
	}

	@Test
	public void testFunctionGraph_Provider_Undefined() {
		createUndefinedFunction();

		isolateProvider();
		hideSatellite();

		setSize(700, 500);// size first, as the positioning is sensitive to the size		
		setZoom(.25);// zoom out a bit to show more vertices
		centerDisplay();
		captureProvider();
		cropAndRemoveHeader(388, 194);
	}

	@Test
	public void testFunctionGraph_Stale_Graph() {
		String address = "406630";
		go(address);// _strlen function

		hideSatellite();

		setSize(612, 300);

		// make a change to trigger the 'stale graph' message
		changeLabel(getAddress(address));

		captureProviderWindow();

		cropAndKeepMessageSection();

		drawRectangleAroundMessageText();
	}

	public void testFunctionGraph_Vertex_Header() {
		String address = "406630";
		go(address);// _strlen function

		setSize(1000, 1000);// size first, as the positioning is sensitive to the size
		setZoom(1.0);// full zoom
		centerDisplay();

		captureProvider();
		cropRootVertexHeader();
	}

	@Test
	public void testFunctionGraph_Grouped_Vertex_Header() {
		String functionAddress = "405d29";
		go(functionAddress);// ___updatetmbcinfo function

		setSize(1000, 1000);// size first, as the positioning is sensitive to the size
		setZoom(1.0);// full zoom

		String a1 = "405d46";
		String a2 = "405d4c";
		FGVertex v1 = vertex(a1);
		FGVertex v2 = vertex(a2);

		GroupedFunctionGraphVertex group = group(null, v1, v2);
		centerDisplay();

		captureProvider();
		cropVertexHeader(group);
	}

	@Test
	public void testFunctionGraph_Pre_Group() {
		String functionAddress = "405d29";
		go(functionAddress);// ___updatetmbcinfo function
		hideSatellite();

		setNestedLayout();

		setSize(1000, 600);// size first, as the positioning is sensitive to the size
		setZoom(1d);// full zoom

		FGVertex root = vertex(functionAddress);

		String a1 = "405d46";
		String a2 = "405d4c";
		FGVertex v1 = vertex(a1);
		FGVertex v2 = vertex(a2);

		pickVertices(v1, v2);
		moveGraphToUpperLeftCorner(root);

		captureProvider();
		cropVertices(root, v1, v2);

//		createGroupButtonCallout_PlayArea(v1, "FunctionGraph_Pre_Group.png");
		createGroupButtonCallout(v1);
	}

	@Test
	public void testFunctionGraph_Post_Group() {
		String functionAddress = "405d29";
		go(functionAddress);// ___updatetmbcinfo function

		setNestedLayout();

		setSize(1000, 500);// size first, as the positioning is sensitive to the size
		setZoom(.85);

		FGVertex root = vertex(functionAddress);
		moveGraphToUpperLeftCorner(root);

		String a1 = "405d46";
		String a2 = "405d4c";
		FGVertex v1 = vertex(a1);
		FGVertex v2 = vertex(a2);

		GroupedFunctionGraphVertex group = group(null, v1, v2);

		captureProvider();
		cropVertices(root, group);
	}

	@Test
	public void testFunctionGraph_Group_Text_Dialog() throws Exception {
		String functionAddress = "405d29";
		go(functionAddress);// ___updatetmbcinfo function

		FGVertex root = vertex(functionAddress);
		moveGraphToUpperLeftCorner(root);

		String a1 = "405d46";
		String a2 = "405d4c";
		FGVertex v1 = vertex(a1);
		FGVertex v2 = vertex(a2);

		DialogComponentProvider dialog = showGroupTextDialog(v1, v2);
		screen.captureDialog(dialog);
		pressButtonByText(dialog.getComponent(), "Cancel");
	}

	@Test
	public void testFunctionGraph_Provider_Header() {

		setSize(800, 400);

		captureProviderWindow();

		GenericHeader providerHeader = getHeader();
		cropHeaderToActions(providerHeader);
	}

	@Test
	public void testFunctionGraph_Vertex_Drop_Shadow() {
		//
		// This image is a bit abnormal.  It is a picture of a vertex next to itself after it
		// has been zoomed out past its 'interaction threshold'.  Further, both vertices are 
		// zoomed out past the point of readability.
		//
		String functionAddress = "4057c4";
		go(functionAddress);// __fflush_nolock

		setNestedLayout();

		setSize(500, 500);// size first, as the positioning is sensitive to the size
		double beforeThresholdZoom = GraphViewerUtils.INTERACTION_ZOOM_THRESHOLD + .01;
		setZoom(beforeThresholdZoom);
		moveGraphToUpperLeftCorner();

		Image graphImage1 = captureGraph();

		double pastThresholdZoom = GraphViewerUtils.INTERACTION_ZOOM_THRESHOLD - .01;
		setZoom(pastThresholdZoom);
		moveGraphToUpperLeftCorner();

		Image graphImage2 = captureGraph();

		// create an empty image onto which we will place both images, side-by-side
		int bufferSpace = 50;
		int graphWidth = graphImage1.getWidth(null) * 2 + bufferSpace;
		int graphHeight = graphImage1.getHeight(null);
		BufferedImage fullImage = screen.createEmptyImage(graphWidth, graphHeight);

		Graphics2D g = (Graphics2D) fullImage.getGraphics();
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		g.drawImage(graphImage1, 0, 0, null);

		int xOffset = graphImage1.getWidth(null) + bufferSpace;
		g.drawImage(graphImage2, xOffset, 0, null);

		int w = 3;
		int x1 = graphImage1.getWidth(null) + (bufferSpace / 2) - (w / 2);// between images
		int y1 = 10;// down a bit

		int h = (graphImage1.getHeight(null) - 10) - y1;

		g.setColor(Color.BLACK);
		g.fillRect(x1, y1, w, h);

		screen.image = fullImage;
	}

// For Debug of callout	
//	public void testCallout() {
//		go("406630"); // _strlen function
//
//		setSize(750, 560); // size first, as the positioning is sensitive to the size
//		centerDisplay();
//
//		doTestCallout();
//	}
//
//	private void doTestCallout() {
//		ComponentProvider provider = screen.getComponentProvider(FunctionGraphProvider.class);
//		JComponent providerComponent = provider.getComponent();
//		DockableComponent parent = getDockableComponent(providerComponent);
//		JButton component = getToolbarButton(provider, "Go To Function Entry Point");
//
//		Rectangle bounds = component.getBounds();
//		Point relativeLocation = bounds.getLocation();
//		Dimension size = bounds.getSize();
//		Point screenLocation = new Point(relativeLocation);
//		SwingUtilities.convertPointToScreen(screenLocation, component.getParent());
//		CalloutComponentInfo info =
//			new CalloutComponentInfo(parent, component, screenLocation, relativeLocation, size);
//
//		createCallout(parent, info);
//		showImage("FunctionGraphPlugin", "FunctionGraph_Post_Group.png");
//	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private Image captureGraph() {
		FGController controller = getFunctionGraphController();
		FGView view = controller.getView();
		VisualizationViewer<FGVertex, FGEdge> viewer = view.getPrimaryGraphViewer();
		FunctionGraph functionGraph = getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGVertex> vertices = graph.getVertices();
		Rectangle layoutBounds =
			GraphViewerUtils.getBoundsForVerticesInLayoutSpace(viewer, vertices);
		Rectangle viewBounds =
			GraphViewerUtils.translateRectangleFromLayoutSpaceToViewSpace(viewer, layoutBounds);

		// add some padding
		int padding = 40;
		viewBounds.x -= padding;
		viewBounds.y -= padding;
		viewBounds.width += (2 * padding);
		viewBounds.height += (2 * padding);

		FGProvider provider = screen.getProvider(FGProvider.class);
		JComponent parent = provider.getComponent();
		DockableComponent dc = getDockableComponent(parent);

		viewBounds = SwingUtilities.convertRectangle(provider.getComponent(), viewBounds, dc);

		captureProvider();

		screen.crop(viewBounds);

		return screen.image;
	}

	private Image captureVertex(FGVertex v) {

		// make sure the vertex is showing
		moveGraphToUpperLeftCorner(v);

		FGController controller = getFunctionGraphController();
		FGView view = controller.getView();
		VisualizationViewer<FGVertex, FGEdge> viewer = view.getPrimaryGraphViewer();

		FGProvider provider = screen.getProvider(FGProvider.class);
		JComponent parent = provider.getComponent();
		DockableComponent dc = getDockableComponent(parent);

		Rectangle vertexBounds = GraphViewerUtils.getVertexBoundsInViewSpace(viewer, v);
		JComponent component = v.getComponent();

		vertexBounds = SwingUtilities.convertRectangle(component.getParent(), vertexBounds, dc);

		captureProvider();

		screen.crop(vertexBounds);

		return screen.image;
	}

	private void cropHeaderToActions(final GenericHeader header) {
		final AtomicReference<Rectangle> ref = new AtomicReference<>();
		runSwing(() -> {
			int actionsWidth = header.getToolBarWidth();

			Window window = windowForComponent(header);
			Rectangle headerBounds = header.getBounds();
			Rectangle bounds = new Rectangle(headerBounds);

			// ugh--apparently the toolbar does not correctly calculate its minimum size
			int padding = 30;

			bounds = SwingUtilities.convertRectangle(header.getParent(), headerBounds, window);
			bounds.x = bounds.x + bounds.width - (actionsWidth + padding);

			padding = 8;// now some vertical padding
			bounds.y -= padding;
			bounds.height += (2 * padding);

			ref.set(bounds);
		});

		Rectangle bounds = ref.get();
		screen.crop(bounds);
	}

	private GenericHeader getHeader() {
		FGController controller = getFunctionGraphController();
		ComponentProvider provider = controller.getProvider();
		DockableComponent dc = getDockableComponent(provider.getComponent());
		return dc.getHeader();
	}

	private void createCallout(JComponent parentComponent, CalloutComponentInfo calloutInfo) {
		// create image of parent with extra space for callout feature
		Image parentImage = screen.captureComponent(parentComponent);

		Callout callout = new Callout();
		screen.image = callout.createCalloutOnImage(parentImage, calloutInfo);

//		createCalloutOnImage(parentImage, parentComponent, calloutInfo);
	}

	private void createGroupButtonCallout(FGVertex v) {

		JButton component = getToolbarButton(v, "Group Vertices");
		FGProvider provider = screen.getProvider(FGProvider.class);
		JComponent parent = provider.getComponent();

		FGController controller = getFunctionGraphController();
		FGView view = controller.getView();
		VisualizationViewer<FGVertex, FGEdge> viewer = view.getPrimaryGraphViewer();

		Rectangle bounds = component.getBounds();
		Dimension size = bounds.getSize();
		Point location = bounds.getLocation();

		JComponent vertexComponent = v.getComponent();
		Point newLocation =
			SwingUtilities.convertPoint(component.getParent(), location, vertexComponent);

		Point relativePoint = GraphViewerUtils.translatePointFromVertexRelativeSpaceToViewSpace(
			viewer, v, newLocation);

		Point screenLocation = new Point(relativePoint);
		SwingUtilities.convertPointToScreen(screenLocation, parent);

		CalloutComponentInfo calloutInfo = new FGCalloutComponentInfo(parent, component,
			screenLocation, relativePoint, size, viewer, v);

		createCallout(parent, calloutInfo);
	}

	private JButton getToolbarButton(FGVertex vertex, String actionName) {

		JComponent component = vertex.getComponent();
		GenericHeader header = (GenericHeader) getInstanceField("genericHeader", component);
		return getToolbarButton(header, actionName);
	}

	private JButton getToolbarButton(GenericHeader header, String actionName) {
		// get the header's 'toolBarMgr'  -  DockableToolBarManager
		Object toolBarMgr = getInstanceField("toolBarMgr", header);

		// get the toolbar manager's 'toolBarManager'  - ToolBarManager
		Object toolBarManager = getInstanceField("toolBarManager", toolBarMgr);

		// get the tool bar manager's manager's 'toolBar'
		JComponent toolbar = (JComponent) getInstanceField("toolBar", toolBarManager);
		Component[] components = toolbar.getComponents();
		for (Component c : components) {
			if (!(c instanceof JButton)) {
				continue;
			}

			String name = c.getName();
			if (actionName.equals(name)) {
				return (JButton) c;
			}
		}

		Assert.fail("Could not find action button");
		return null;
	}

	private void drawRectangleAroundMessageText() {
		int imageHeight = screen.image.getHeight(null);

		int boxSize = 60;
		int boxThickness = 3;
		int x = 1;
		int y = imageHeight - boxSize;
		int w = 250;
		int h = boxSize - boxThickness;
		Rectangle rect = new Rectangle(x, y, w, h);

		// drop shadow
		Color color = Color.GRAY;
		screen.drawRectangle(color, rect, boxThickness);

		// box
		x -= 1;
		y -= 2;
		color = new Color(0xB5, 0xDE, 0x2F);
		rect.x = x;
		rect.y = y;
		screen.drawRectangle(color, rect, boxThickness);
	}

	private void changeLabel(Address address) {
		AddLabelCmd cmd = new AddLabelCmd(address, "Test.Label", SourceType.USER_DEFINED);
		int id = program.startTransaction("Test");
		try {
			cmd.applyTo(program);
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	private void cropRootVertexHeader() {
		FunctionGraph functionGraph = getFunctionGraph();
		FGVertex rootVertex = functionGraph.getRootVertex();
		cropVertexHeader(rootVertex);
	}

	private void cropVertexHeader(FGVertex vertex) {
		FGPrimaryViewer viewer = getPrimaryGraphViewer();
		Rectangle bounds = GraphViewerUtils.getVertexBoundsInViewSpace(viewer, vertex);

		DockableComponent dockableComponent = getDockableComponent(viewer);
		Point loc = SwingUtilities.convertPoint(viewer, bounds.getLocation(), dockableComponent);
		bounds.setLocation(loc);

		//
		// We want to keep the whole header, with a buffer space around it of about 10px
		//
		Rectangle area = new Rectangle(bounds);
		int offset = 10;
		area.x -= offset;
		area.y -= offset;
		area.width += (2 * offset);
		area.height = 50;
		screen.crop(area);
	}

	private void cropVertices(FGVertex... vertices) {

		FGPrimaryViewer viewer = getPrimaryGraphViewer();
		List<FGVertex> list = Arrays.asList(vertices);
		Rectangle bounds = GraphViewerUtils.getBoundsForVerticesInLayoutSpace(viewer, list);
		bounds = GraphViewerUtils.translateRectangleFromLayoutSpaceToViewSpace(viewer, bounds);

		DockableComponent dockableComponent = getDockableComponent(viewer);
		bounds = SwingUtilities.convertRectangle(viewer, bounds, dockableComponent);

		//
		// Put a buffer space around the area
		//
		Rectangle area = new Rectangle(bounds);
		int offset = 20;
		area.x -= offset;
		area.y -= offset;
		area.width += (2 * offset);
		area.height += (2 * offset);
		screen.crop(area);
	}

	private void cropAndKeepMessageSection() {
		int imageWidth = screen.image.getWidth(null);
		int imageHeight = screen.image.getHeight(null);

		// keep about 100 pixels of display to get the message area and a bit above
		Rectangle area = new Rectangle();
		area.x = 0;
		area.y = imageHeight - 120;
		area.width = imageWidth;
		area.height = 120;
		screen.crop(area);
	}

	private void go(String address) {
		goToAddress(address);
	}

	private void centerDisplay() {
		FunctionGraph functionGraph = getFunctionGraph();
		FGVertex v = functionGraph.getRootVertex();
		setVertexToCenterTop(v);
	}

	private void moveGraphToUpperLeftCorner(final FGVertex anchorVertex) {
		waitForBusyGraph();

		runSwing(() -> {
			FGPrimaryViewer viewer = getPrimaryGraphViewer();
			Point p = getOffsetFromUpperLeftForVertexInLayoutSpace(viewer, anchorVertex);
			moveViewerLocationWithoutAnimation(p);
		});
	}

	private void moveGraphToUpperLeftCorner() {
		waitForBusyGraph();

		final FunctionGraph functionGraph = getFunctionGraph();
		runSwing(() -> {
			FGController controller = getFunctionGraphController();
			FGView view = controller.getView();
			VisualizationViewer<FGVertex, FGEdge> viewer = view.getPrimaryGraphViewer();

			FunctionGraph graph = functionGraph;
			Collection<FGVertex> vertices = graph.getVertices();
			Rectangle layoutBounds =
				GraphViewerUtils.getBoundsForVerticesInLayoutSpace(viewer, vertices);
			Rectangle viewBounds =
				GraphViewerUtils.translateRectangleFromLayoutSpaceToViewSpace(viewer, layoutBounds);

			Point location = viewBounds.getLocation();
			Point layoutPoint = getOffsetFromUpperLeftForViewPointInLayoutSpace(viewer, location);

			moveViewerLocationWithoutAnimation(layoutPoint);
		});
	}

	private <V, E> Point getOffsetFromUpperLeftForVertexInLayoutSpace(
			VisualizationServer<V, E> viewer, V vertex) {

		//
		// We need an offset from the current vertex to the center top of the viewer
		//
		Rectangle vertexBoundsInViewSpace =
			GraphViewerUtils.getVertexBoundsInViewSpace(viewer, vertex);
		Point vertexLocationInViewSpace = vertexBoundsInViewSpace.getLocation();

		// this padding is enough to not see the edges for most operations--it can be increased
		int xWithPadding = 20;
		int yWithPadding = 20;
		Double point = new Point2D.Double(xWithPadding, yWithPadding);// upper, left

		Point vertexPointInLayoutSpace = GraphViewerUtils.translatePointFromViewSpaceToLayoutSpace(
			vertexLocationInViewSpace, viewer);
		Point upperLeftInLayoutSpace =
			GraphViewerUtils.translatePointFromViewSpaceToLayoutSpace(point, viewer);

		double offsetX = upperLeftInLayoutSpace.getX() - vertexPointInLayoutSpace.getX();
		double offsetY = upperLeftInLayoutSpace.getY() - vertexPointInLayoutSpace.getY();
		return new Point((int) offsetX, (int) offsetY);
	}

	private <V, E> Point getOffsetFromUpperLeftForViewPointInLayoutSpace(
			VisualizationServer<V, E> viewer, Point viewPoint) {

		// this padding is enough to not see the edges for most operations--it can be increased
		int xWithPadding = 50;
		int yWithPadding = 50;
		Double offsetPoint = new Point2D.Double(xWithPadding, yWithPadding);// upper, left

		Point vertexPointInLayoutSpace =
			GraphViewerUtils.translatePointFromViewSpaceToLayoutSpace(viewPoint, viewer);
		Point viewOffsetPointInLayoutSpace =
			GraphViewerUtils.translatePointFromViewSpaceToLayoutSpace(offsetPoint, viewer);

		double offsetX = viewOffsetPointInLayoutSpace.getX() - vertexPointInLayoutSpace.getX();
		double offsetY = viewOffsetPointInLayoutSpace.getY() - vertexPointInLayoutSpace.getY();
		return new Point((int) offsetX, (int) offsetY);
	}

	private void isolateProvider() {
		ComponentProvider provider = tool.getWindowManager().getComponentProvider(FGProvider.class);
		screen.moveProviderToItsOwnWindow(provider);
	}

	private void setSize(final int width, final int height) {
		this.width = width;
		this.height = height;

		final ComponentProvider provider =
			tool.getWindowManager().getComponentProvider(FGProvider.class);
		runSwing(() -> {
			Window window = tool.getWindowManager().getProviderWindow(provider);
			if (window == null) {
				throw new AssertException("Could not find window for " +
					"provider--is it showing?: " + provider.getName());
			}

			window.setSize(new Dimension(width, height));
		});
	}

	private void captureProvider() {
		screen.captureIsolatedProvider(FGProvider.class, width, height);
	}

	private void captureProviderWindow() {
		screen.captureIsolatedProviderWindow(FGProvider.class, width, height);
	}

	private void cropAndRemoveHeader(int w, int h) {
		int imageWidth = screen.image.getWidth(null);
		int x = (imageWidth / 2) - (w / 2);
		int y = 20;// down a bit from the top
		Rectangle newBounds = new Rectangle(x, y, w, h);
		screen.crop(newBounds);
	}

	private void createUndefinedFunction() {
		String address = "00401c25";
		go(address);

		DeleteFunctionCmd cmd = new DeleteFunctionCmd(getAddress(address));
		int id = program.startTransaction("Test");
		try {
			cmd.applyTo(program);
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	private DialogComponentProvider showGroupTextDialog(FGVertex... vertices) {
		HashSet<FGVertex> set = new HashSet<>();
		for (FGVertex v : vertices) {
			set.add(v);
		}

		pickVertices(set);

		FGVertex aVertex = vertices[0];
		JComponent component = getComponent(aVertex);
		DockingAction action = (DockingAction) TestUtils.getInstanceField("groupAction", component);
		performAction(action, graphProvider, false);
		waitForAnimation();

		return waitForDialogComponent(MultiLineInputDialog.class);
	}

	private void pickVertices(FGVertex... vertices) {
		pickVertices(new HashSet<>(Arrays.asList(vertices)));
	}

	private JComponent getComponent(final FGVertex vertex) {
		final AtomicReference<JComponent> reference = new AtomicReference<>();
		runSwing(() -> reference.set(vertex.getComponent()));
		return reference.get();
	}

	private void setNestedLayout() {

		Object actionManager = getInstanceField("actionManager", graphProvider);
		@SuppressWarnings("unchecked")
		final MultiStateDockingAction<Class<? extends FGLayoutProvider>> action =
			(MultiStateDockingAction<Class<? extends FGLayoutProvider>>) getInstanceField(
				"layoutAction", actionManager);
		runSwing(() -> {
			List<ActionState<Class<? extends FGLayoutProvider>>> states =
				action.getAllActionStates();
			for (ActionState<Class<? extends FGLayoutProvider>> state : states) {
				Class<? extends FGLayoutProvider> layoutClass = state.getUserData();
				if (layoutClass.getSimpleName().equals("DecompilerNestedLayoutProvider")) {
					action.setCurrentActionState(state);
					return;
				}
			}

			throw new RuntimeException("Could not find layout!!");
		});
	}

	private void createGroupButtonCallout_PlayArea(final FGVertex v, final String imageName) {

		FGProvider provider = screen.getProvider(FGProvider.class);
		Window window = windowForComponent(provider.getComponent());
		final JDialog dialog = new JDialog(window);
		dialog.setModal(true);

		JPanel panel = new JPanel(new BorderLayout());
		JButton button = new JButton("Repaint");
		button.addActionListener(e -> new Thread() {
			@Override
			public void run() {
				Thread.currentThread().setName("Show Image[" + System.identityHashCode(this) + "]");

				createGroupButtonCallout(v);
				screen.saveOrDisplayImage(imageName);
			}
		}.start());

		JButton closeButton = new JButton("Close");
		closeButton.addActionListener(e -> dialog.setVisible(false));

		panel.add(button);
		panel.add(closeButton, BorderLayout.SOUTH);
		dialog.getContentPane().add(panel);

		dialog.setSize(300, 200);
		dialog.setLocation(1300, 100);
		dialog.setVisible(true);
	}

	@SuppressWarnings("rawtypes")
	private void setLayout() {
		long start = System.currentTimeMillis();
		Object actionManager = getInstanceField("actionManager", graphProvider);
		final MultiStateDockingAction<?> action =
			(MultiStateDockingAction<?>) getInstanceField("layoutAction", actionManager);

		Object minCrossState = null;
		List<?> states = action.getAllActionStates();
		for (Object state : states) {
			if (((ActionState) state).getName().indexOf("Nested Code Layout") != -1) {
				minCrossState = state;
				break;
			}
		}

		assertNotNull("Could not find min cross layout!", minCrossState);

		//@formatter:off
		invokeInstanceMethod( "setCurrentActionState", 
							  action, 
							  new Class<?>[] { ActionState.class },
							  new Object[] { minCrossState });
		//@formatter:on

		runSwing(() -> action.actionPerformed(new ActionContext()));

		// wait for the threaded graph layout code
		FGController controller = getFunctionGraphController();
		waitForBusyRunManager(controller);
		waitForAnimation();
		getPrimaryGraphViewer().repaint();
		waitForPostedSwingRunnables();

		long end = System.currentTimeMillis();
		Msg.debug(this, "relayout time: " + ((end - start) / 1000.0) + "s");
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class MyScreen extends GhidraScreenShotGenerator {

		public MyScreen() {
			super();
		}

		@Override
		public void loadProgram() {
			// do nothing, we will put our own copy inside the screen
		}

		@Override
		// overridden so that we use the outer class's name when finding the help topic 
		protected File getHelpTopic() {
			Class<?> clazz = FunctionGraphPluginScreenShots.class;
			String simpleName = clazz.getSimpleName();
			simpleName = simpleName.replace("ScreenShots", "");
			File helpTopicDir = getHelpTopicDir(simpleName);
			assertNotNull("Unable to find help topic for test file: " + clazz.getName(),
				helpTopicDir);
			return helpTopicDir;
		}
	}

	private class FGCalloutComponentInfo extends CalloutComponentInfo {

		private VisualizationViewer<FGVertex, FGEdge> viewer;
		private FGVertex vertex;

		FGCalloutComponentInfo(Component destinationComponent, Component component,
				Point locationOnScreen, Point relativeLocation, Dimension size,
				VisualizationViewer<FGVertex, FGEdge> viewer, FGVertex vertex) {

			super(destinationComponent, component, locationOnScreen, relativeLocation, size);
			this.viewer = viewer;
			this.vertex = vertex;
		}

		@Override
		public Point convertPointToParent(Point location) {
			// TODO: this won't work for now if the graph is scaled.   This is because there is
			//       point information that is calculated by the client of this class that does 
			//       not take into account the scaling of the graph.  This is a known issue--
			//       don't use this class when the graph is scaled.
			return location;
		}
	}
}
