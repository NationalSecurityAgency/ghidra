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
package datagraph.graph;

import static org.junit.Assert.*;

import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.junit.*;

import datagraph.*;
import datagraph.data.graph.*;
import datagraph.data.graph.panel.model.row.DataRowObject;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingActionIf;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.event.picking.GPickedState;
import ghidra.graph.viewer.options.VisualGraphOptions;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.util.ProgramLocation;
import ghidra.test.*;

public class DataGraphProviderTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private DataGraphPlugin dataGraphPlugin;
	private CodeBrowserPlugin codeBrowser;
	private ProgramDB program;
	private Structure employerStruct;
	private Structure addressStruct;
	private Structure personStruct;
	private ToyProgramBuilder builder;
	private DataGraphProvider provider;
	private DegController controller;
	private DataExplorationGraph graph;

	@Before
	public void setUp() throws Exception {

		setErrorGUIEnabled(false);
		createStructures();

		env = new TestEnv();
		tool = env.getTool();

		initializeTool();
		goToAddress("0x300");
		graph = showDataGraph();
		turnOffAnimation();
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	@Test
	public void testGraphHasInitialVertex() {

		DegVertex vertex = graph.getRoot();
		assertTitle("Person_00000300 @ 00000300", vertex);
	}

	@Test
	public void testExpandInsideVertex() {
		assertEquals(1, graph.getVertexCount());
		DegVertex vertex = graph.getRoot();

		//@formatter:off
		assertField(vertex,
			"Person",
			"	Name",
			"	Age",
			"	Address",
			"	Employer"
		);
		//@formatter:on

		expand(vertex, "	Employer");

		//@formatter:off
		assertField(vertex,
			"Person",
			"	Name",
			"	Age",
			"	Address",
			"	Employer",
			"		Company",
			"		Address"
		);
		//@formatter:on
	}

	@Test
	public void testOpenChildNode() {

		assertEquals(1, graph.getVertexCount());
		DegVertex vertex = graph.getRoot();

		openRow(vertex, "	Address");

		assertEquals(2, graph.getVertexCount());
		DegVertex newVertex = getVertex("Address_00000100 @ 00000100");
		assertNotNull(newVertex);
	}

	@Test
	public void testOutgoingReferencesAction() {
		openOutgoingReferences();
		assertEquals(3, graph.getVertexCount());
	}

	@Test
	public void testIncommingReferencesAction() {
		openIncomingReferences();
		assertEquals(2, graph.getVertexCount());
	}

	private void openIncomingReferences() {
		DockingActionIf inRefsAction = getLocalAction(provider, "Incoming References");
		DegContext context = (DegContext) provider.getActionContext(null);
		assertNotNull(context.getVertex());

		performAction(inRefsAction, context, true);
	}

	private void openOutgoingReferences() {
		DockingActionIf outRefsAction = getLocalAction(provider, "Outgoing References");
		DegContext context = (DegContext) provider.getActionContext(null);
		assertNotNull(context.getVertex());

		performAction(outRefsAction, context, true);
	}

	@Test
	public void testCloseSelectedVerticesAction() {
		DockingActionIf closeAction = getLocalAction(provider, "Delete Vertices");
		DegContext context = (DegContext) provider.getActionContext(null);
		assertEquals(1, context.getSelectedVertices().size());
		assertFalse(closeAction.isEnabledForContext(context));

		openOutgoingReferences();
		Set<DegVertex> newVertices = getNonRootVertices();
		selectVertices(newVertices);

		assertEquals(2, context.getSelectedVertices().size());
		assertTrue(closeAction.isEnabledForContext(context));

		performAction(closeAction);
		assertEquals(1, graph.getVertexCount());

	}

	@Test
	public void testOrientGraphAction() {
		openOutgoingReferences();
		DegVertex root = graph.getRoot();

		Set<DegVertex> newVertices = getNonRootVertices();
		DegVertex other = newVertices.iterator().next();
		assertNull(root.getSourceVertex());
		assertEquals(root, other.getSourceVertex());

		selectVertices(Set.of(other));
		DockingActionIf orientAction = getLocalAction(provider, "Set Original Vertex");
		DegContext context = (DegContext) provider.getActionContext(null);
		performAction(orientAction, context, true);
		assertEquals(other, graph.getRoot());

		assertEquals(other, root.getSourceVertex());
		assertNull(other.getSourceVertex());

	}

	@Test
	public void testExpandFormatAction() {
		assertTrue(controller.isCompactFormat());
		ToggleDockingActionIf expandedFormatAction =
			(ToggleDockingActionIf) getLocalAction(provider, "Show Expanded Format");

		performAction(expandedFormatAction, true);
		assertFalse(controller.isCompactFormat());

	}

	@Test
	public void testNavigationOut() {
		openOutgoingReferences();
		Collection<DegVertex> vertices = graph.getVertices();
		for (DegVertex dgVertex : vertices) {
			selectVertices(Set.of(dgVertex));
			Address vertexAddress = dgVertex.getAddress();
			Address listingAddress = codeBrowser.getCurrentAddress();
			assertEquals(vertexAddress, listingAddress);
		}
	}

	@Test
	public void testNavigateIn() {
		openOutgoingReferences();
		turnOnNavigationIn();

		goToListing(0x100);
		DegVertex focused = getFocusedVertex();
		assertEquals(0x100, focused.getAddress().getOffset());

		goToListing(0x200);
		focused = getFocusedVertex();
		assertEquals(0x200, focused.getAddress().getOffset());

		goToListing(0x300);
		focused = getFocusedVertex();
		assertEquals(0x300, focused.getAddress().getOffset());

	}

	@Test
	public void testVertexCloseAction() {
		openRow(graph.getRoot(), "	Address");
		DegVertex newVertex = getVertex("Address_00000100 @ 00000100");
		DockingActionIf closeAction = newVertex.getAction("Close Vertex");
		assertTrue(closeAction.isEnabledForContext(provider.getActionContext(null)));

		assertEquals(2, graph.getVertexCount());
		performAction(closeAction);
		assertEquals(1, graph.getVertexCount());
	}

	@Test
	public void testCantCloseRootVertex() {
		DegVertex root = graph.getRoot();
		DockingActionIf closeAction = root.getAction("Close Vertex");
		assertFalse(closeAction.isEnabledForContext(provider.getActionContext(null)));
	}

	@Test
	public void testExpandAllCollapseAllAction() {
		DegVertex root = graph.getRoot();
		DockingActionIf expandAction = root.getAction("Expand All");
		DockingActionIf collapseAction = root.getAction("Collapse All");

		assertRowCount(root, 5);

		performAction(expandAction);

		assertRowCount(root, 47);

		performAction(collapseAction);

		assertRowCount(root, 1);
	}

	private void assertRowCount(DegVertex vertex, int expectedRowCount) {
		List<DataRowObject> rowObjects = ((DataDegVertex) vertex).getRowObjects();
		assertEquals(expectedRowCount, rowObjects.size());
	}

	private DegVertex getFocusedVertex() {
		Collection<DegVertex> vertices = graph.getVertices();
		for (DegVertex dgVertex : vertices) {
			if (dgVertex.isFocused()) {
				return dgVertex;
			}
		}
		return null;
	}

	private void goToListing(long address) {
		runSwing(() -> codeBrowser.goTo(new ProgramLocation(program, builder.addr(address))));
	}

	private void turnOnNavigationIn() {
		ToggleDockingActionIf navigateInAction =
			(ToggleDockingActionIf) getLocalAction(provider,
				"Navigate on Incoming Location Changes");

		performAction(navigateInAction, true);

	}

	private Set<DegVertex> getNonRootVertices() {
		Set<DegVertex> set = new HashSet<>(graph.getVertices());
		set.remove(graph.getRoot());
		return set;
	}

	private void openRow(DegVertex vertex, String text) {
		int row = getRowNumber(vertex, text);
		runSwing(() -> ((DataDegVertex) vertex).openPointerReference(row));
		waitForAnimation();
	}

	private DegVertex getVertex(String title) {
		Collection<DegVertex> vertices = graph.getVertices();
		for (DegVertex v : vertices) {
			String vertexTitle = v.getTitle();
			if (title.equals(vertexTitle)) {
				return v;
			}
		}
		return null;
	}

	private void expand(DegVertex v, String text) {

		int row = getRowNumber(v, text);
		DataDegVertex dataVertex = (DataDegVertex) v;
		runSwing(() -> dataVertex.expand(row));
	}

	private int getRowNumber(DegVertex v, String text) {
		List<String> actualRows = getRowsAsText((DataDegVertex) v);
		int row = actualRows.indexOf(text);
		assertTrue(row >= 0);
		return row;
	}

	private void assertField(DegVertex v, String... expectedRows) {

		List<String> actualRows = getRowsAsText((DataDegVertex) v);
		assertEquals(expectedRows.length, actualRows.size());
		List<String> expectedList = Arrays.asList(expectedRows);
		assertListEqualOrdered(expectedList, actualRows);
	}

	private List<String> getRowsAsText(DataDegVertex v) {

		List<DataRowObject> rows = runSwing(() -> v.getRowObjects());

		//@formatter:off
		List<String> asText = rows.stream().map(r -> {
			int indent = r.getIndentLevel();
			String name = indent == 0 ? r.getDataType() : r.getName();
			String indentation = StringUtils.repeat("\t", indent);
			return indentation + name;
		})
		.collect(Collectors.toList());
		//@formatter:on

		return asText;
	}

	private void assertTitle(String expected, DegVertex vertex) {
		String actual = runSwing(() -> vertex.getTitle());
		assertEquals(expected, actual);
	}

	private DataExplorationGraph showDataGraph() {
		DockingActionIf action = getAction(dataGraphPlugin, "Display Data Graph");
		assertNotNull(action);
		performAction(action);
		provider = waitForComponentProvider(DataGraphProvider.class);
		controller = provider.getController();
		return controller.getGraph();
	}

	protected ProgramLocation getLocationForAddressString(String addressString) {
		Address address = builder.addr(addressString);
		return new ProgramLocation(program, address);
	}

	protected void goToAddress(String addressString) {
		ProgramLocation location = getLocationForAddressString(addressString);
		codeBrowser.goTo(location, true);

		waitForSwing();
	}

	protected void initializeTool() throws Exception {
		installPlugins();

		createProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		showTool(tool);
	}

	protected void installPlugins() throws PluginException {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(DataGraphPlugin.class.getName());

		dataGraphPlugin = env.getPlugin(DataGraphPlugin.class);
		codeBrowser = env.getPlugin(CodeBrowserPlugin.class);
	}

	protected void createProgram() throws Exception {

		builder = new ToyProgramBuilder("sample", true);
		builder.createMemory("data", "0x0100", 0x1000);
		createStructures();

		createAddressData(0x100, "123 Main St", "Springfield", "MD", "12211");
		createAddressData(0x200, "987 1st St", "Columbia", "MD", "22331");

		createPersonData(0x300, "Jane Doe", 32, 0x100, "IBM", 0x200);

		builder.putAddress("0x400", "0x300");
		builder.applyDataType("0x400", new PointerDataType(personStruct));

		program = builder.getProgram();
	}

	private void createAddressData(long addr, String street, String city, String state,
			String zip) throws Exception {

		builder.setString(addrString(addr), street);
		builder.setString(addrString(addr + 20), city);
		builder.setString(addrString(addr + 40), state);
		builder.setString(addrString(addr + 42), zip);
		builder.applyDataType(addrString(addr), addressStruct);
	}

	private void createPersonData(long addr, String name, int age, long addressPointer,
			String companyName, long companyAddressPointer) throws Exception {

		builder.setString(addrString(addr), name);
		builder.setInt(addrString(addr + 20), age);
		builder.putAddress(addrString(addr + 24), addrString(addressPointer));
		builder.setString(addrString(addr + 28), companyName);
		builder.putAddress(addrString(addr + 48), addrString(companyAddressPointer));

		builder.applyDataType(addrString(addr), personStruct);
	}

	private String addrString(long offset) {
		return builder.addr(offset).toString();
	}

	private void createStructures() {
		employerStruct = createEmployerStruct();
		addressStruct = createAddressStruct();
		personStruct = createPersonStruct();
	}

	private Structure createPersonStruct() {
		Structure person = new StructureDataType("Person", 0);

		person.add(getCharField(20), "Name", "");
		person.add(new IntegerDataType(), "Age", "");
		person.add(new PointerDataType(addressStruct), "Address", "");
		person.add(employerStruct, "Employer", "");

		return person;
	}

	private Structure createEmployerStruct() {
		Structure employer = new StructureDataType("Employer", 0);
		employer.add(getCharField(20), "Company", "");
		employer.add(new PointerDataType(addressStruct), "Address", "");
		return employer;
	}

	private Structure createAddressStruct() {
		Structure address = new StructureDataType("Address", 0);

		address.add(getCharField(20), "Street", "");
		address.add(getCharField(20), "City", "");
		address.add(getCharField(2), "State", "");
		address.add(getCharField(5), "Zip", "");
		return address;
	}

	private DataType getCharField(int size) {
		return new ArrayDataType(new CharDataType(), size);
	}

	private void waitForAnimation() {

		VisualGraphViewUpdater<DegVertex, DegEdge> updater = getGraphUpdater();
		if (updater == null) {
			return; // nothing to wait for; no active graph
		}

		waitForSwing();
		int tryCount = 3;
		while (tryCount++ < 5 && updater.isBusy()) {
			waitForConditionWithoutFailing(() -> !updater.isBusy());
		}
		waitForSwing();

		assertFalse(updater.isBusy());
	}

	private VisualGraphViewUpdater<DegVertex, DegEdge> getGraphUpdater() {
		GraphViewer<DegVertex, DegEdge> viewer = controller.getPrimaryViewer();
		VisualGraphViewUpdater<DegVertex, DegEdge> updater = viewer.getViewUpdater();
		assertNotNull(updater);
		return updater;
	}

	private void selectVertices(Set<DegVertex> newVertices) {
		GraphViewer<DegVertex, DegEdge> viewer = controller.getPrimaryViewer();
		GPickedState<DegVertex> pickState = viewer.getGPickedVertexState();
		runSwing(() -> {
			pickState.clear();
			for (DegVertex dgVertex : newVertices) {
				pickState.pick(dgVertex, true);
			}
		});
		waitForSwing();
	}

	private void turnOffAnimation() {
		runSwing(() -> {
			GraphComponent<DegVertex, DegEdge, DataExplorationGraph> comp =
				controller.getView().getGraphComponent();
			VisualGraphOptions graphOptions = comp.getGraphOptions();
			graphOptions.setUseAnimation(false);
		});
	}

}
