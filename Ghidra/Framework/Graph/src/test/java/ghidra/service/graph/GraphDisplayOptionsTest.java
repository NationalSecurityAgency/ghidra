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
package ghidra.service.graph;

import static org.junit.Assert.*;

import java.awt.Color;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import docking.FakeDockingTool;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.util.HelpLocation;
import ghidra.util.WebColors;

public class GraphDisplayOptionsTest {

	private GraphType graphType;
	private GraphDisplayOptions options;

	@Before
	public void setUp() {
		List<String> vertexTypes = Arrays.asList("V1", "V2", "V3");
		List<String> edgeTypes = Arrays.asList("E1", "E2", "E3");
		graphType = new GraphType("Test", "Test Description", vertexTypes, edgeTypes);
		options = new GraphDisplayOptions(graphType);
	}

	@Test
	public void testSetAndGetDefaultVertexShape() {
		options.setDefaultVertexShape(VertexShape.STAR);
		assertEquals(VertexShape.STAR, options.getDefaultVertexShape());
	}

	@Test
	public void testSetAndGetDefaultVertexColor() {
		options.setDefaultVertexColor(Color.MAGENTA);
		assertEquals(Color.MAGENTA, options.getDefaultVertexColor());
	}

	@Test
	public void testSetAndGetDefaultEdgeColor() {
		options.setDefaultEdgeColor(Color.MAGENTA);
		assertEquals(Color.MAGENTA, options.getDefaultEdgeColor());
	}

	@Test
	public void testSetAndGetVertexLabelOverride() {
		assertEquals(null, options.getVertexLabelOverride());
		options.setVertexLabelOverrideAttributeKey("LABEL");
		assertEquals("LABEL", options.getVertexLabelOverride());
	}

	@Test
	public void testSetAndGetVertexColorOverrideAttributeKey() {
		assertEquals(null, options.getVertexColorOverrideAttributeKey());
		options.setVertexColorOverrideAttributeKey("COLOR");
		assertEquals("COLOR", options.getVertexColorOverrideAttributeKey());
	}

	@Test
	public void testSetAndGetEdgeColorOverrideAttributeKey() {
		assertEquals(null, options.getEdgeColorOverrideAttributeKey());
		options.setEdgeColorOverrideAttributeKey("COLOR");
		assertEquals("COLOR", options.getEdgeColorOverrideAttributeKey());
	}

	@Test
	public void testSetAndGetVertexShapeOverrideAttributeKey() {
		assertEquals(null, options.getVertexShapeOverrideAttributeKey());
		options.setVertexColorOverrideAttributeKey("SHAPE");
		assertEquals("SHAPE", options.getVertexColorOverrideAttributeKey());
	}

	@Test
	public void testGetVertexLabel() {
		AttributedVertex vertex = new AttributedVertex("Foo");
		assertEquals("Foo", options.getVertexLabel(vertex));
	}

	@Test
	public void testGetVertexLabelWithLableOverride() {
		options.setVertexLabelOverrideAttributeKey("Label");
		AttributedVertex vertex = new AttributedVertex("Foo");
		vertex.setAttribute("Label", "Bar");
		assertEquals("Bar", options.getVertexLabel(vertex));
	}

	@Test
	public void testGetVertexShape() {
		options.setVertexShape("V1", VertexShape.DIAMOND);
		options.setVertexShape("V2", VertexShape.PENTAGON);
		AttributedVertex vertex = new AttributedVertex("Foo");

		vertex.setVertexType("V1");
		assertEquals(VertexShape.DIAMOND, options.getVertexShape(vertex));

		vertex.setVertexType("V2");
		assertEquals(VertexShape.PENTAGON, options.getVertexShape(vertex));
	}

	@Test
	public void testGetVertexShapeWithOverride() {
		options.setVertexShape("V1", VertexShape.DIAMOND);
		options.setVertexShapeOverrideAttributeKey("Shape");
		AttributedVertex vertex = new AttributedVertex("Foo");

		vertex.setVertexType("V1");
		assertEquals(VertexShape.DIAMOND, options.getVertexShape(vertex));

		vertex.setAttribute("Shape", VertexShape.ELLIPSE.getName());
		assertEquals(VertexShape.ELLIPSE, options.getVertexShape(vertex));
	}

	@Test
	public void testGetVertexColor() {
		options.setVertexColor("V1", Color.RED);
		options.setVertexColor("V2", Color.GREEN);
		AttributedVertex vertex = new AttributedVertex("Foo");

		assertEquals(options.getDefaultVertexColor(), options.getVertexColor(vertex));

		vertex.setVertexType("V1");
		assertEquals(Color.RED, options.getVertexColor(vertex));

		vertex.setVertexType("V2");
		assertEquals(Color.GREEN, options.getVertexColor(vertex));
	}

	@Test
	public void testGetVertexColorWithOverride() {
		options.setVertexColor("V1", Color.RED);
		options.setVertexColor("V2", Color.GREEN);
		options.setVertexColorOverrideAttributeKey("Color");
		AttributedVertex vertex = new AttributedVertex("Foo");

		vertex.setVertexType("V1");
		assertEquals(Color.RED, options.getVertexColor(vertex));

		vertex.setAttribute("Color", WebColors.toString(Color.BLUE));

		assertEquals(Color.BLUE, options.getVertexColor(vertex));
	}

	@Test
	public void testGetEdgeColor() {
		options.setEdgeColor("E1", Color.RED);
		options.setEdgeColor("E2", Color.GREEN);
		AttributedEdge edge = new AttributedEdge("1");
		assertEquals(options.getDefaultEdgeColor(), options.getEdgeColor(edge));

		edge.setEdgeType("E1");
		assertEquals(Color.RED, options.getEdgeColor(edge));

		edge.setEdgeType("E2");
		assertEquals(Color.GREEN, options.getEdgeColor(edge));
	}

	@Test
	public void testGetEdgeColorWithOverride() {
		options.setEdgeColor("E1", Color.RED);
		options.setEdgeColor("E2", Color.GREEN);
		options.setEdgeColorOverrideAttributeKey("Color");
		AttributedEdge edge = new AttributedEdge("1");
		assertEquals(options.getDefaultEdgeColor(), options.getEdgeColor(edge));

		edge.setEdgeType("E1");
		assertEquals(Color.RED, options.getEdgeColor(edge));

		edge.setAttribute("Color", WebColors.toString(Color.BLUE));

		assertEquals(Color.BLUE, options.getEdgeColor(edge));
	}

	@Test
	public void testGetEdgePriority() {
		assertEquals(0, options.getEdgePriority("E1").intValue());
		assertEquals(1, options.getEdgePriority("E2").intValue());
	}

	@Test
	public void testGetFavoredEdgeType() {
		// favored edge defaults to first edge defined
		assertEquals("E1", options.getFavoredEdgeType());
		options.setFavoredEdgeType("E2");
		assertEquals("E2", options.getFavoredEdgeType());
	}

	@Test
	public void testGetVertexColorForType() {
		assertEquals(options.getDefaultVertexColor(), options.getVertexColor("V1"));
		options.setVertexColor("V1", Color.RED);
		assertEquals(Color.RED, options.getVertexColor("V1"));
	}

	@Test
	public void testGetVertexShapeForType() {
		assertEquals(options.getDefaultVertexShape(), options.getVertexShape("V1"));
		options.setVertexShape("V1", VertexShape.STAR);
		assertEquals(VertexShape.STAR, options.getVertexShape("V1"));
	}

	@Test
	public void testGetEdgeColorForType() {
		assertEquals(options.getDefaultEdgeColor(), options.getEdgeColor("V1"));
		options.setEdgeColor("E1", Color.RED);
		assertEquals(Color.RED, options.getEdgeColor("E1"));
	}

	@Test
	public void testRegisterOptions() {
		ToolOptions toolOptions = new ToolOptions("Test");
		HelpLocation help = new HelpLocation("Topic", "anchor");
		options.registerOptions(toolOptions, help);

		Options graphDisplayOptions = toolOptions.getOptions(options.getRootOptionsName());
		assertNotNull(graphDisplayOptions);

		Options vertexColorOptions = graphDisplayOptions.getOptions("Vertex Colors");
		List<String> leafOptionNames = vertexColorOptions.getLeafOptionNames();
		assertEquals(Arrays.asList("V1", "V2", "V3"), leafOptionNames);
		assertEquals(options.getDefaultVertexColor(),
			vertexColorOptions.getColor("V1", Color.WHITE));

		Options vertexShapeOptions = graphDisplayOptions.getOptions("Vertex Shapes");
		leafOptionNames = vertexShapeOptions.getLeafOptionNames();
		assertEquals(Arrays.asList("V1", "V2", "V3"), leafOptionNames);
		assertEquals(options.getDefaultVertexShape().getName(),
			vertexShapeOptions.getString("V1", "Bob"));

		Options edgeColorOptions = graphDisplayOptions.getOptions("Edge Colors");
		leafOptionNames = edgeColorOptions.getLeafOptionNames();
		assertEquals(Arrays.asList("E1", "E2", "E3"), leafOptionNames);
		assertEquals(options.getDefaultEdgeColor(),
			edgeColorOptions.getColor("E1", Color.WHITE));

		Options miscellaneousOptions = graphDisplayOptions.getOptions("Miscellaneous");
		leafOptionNames = miscellaneousOptions.getLeafOptionNames();
		assertEquals(Arrays.asList("Use Icons", "Max Graph Size",
			"Selected Vertex Color", "Default Layout Algorithm", "Default Vertex Color",
			"Default Vertex Shape", "Selected Edge Color", "Label Position",
			"Default Edge Color", "Font", "Favored Edge Type"), leafOptionNames);

	}

	@Test
	public void testChangingToolOptionsAffectsGraph() {
		FakeDockingTool tool = new FakeDockingTool();
		ToolOptions toolOptions = tool.getOptions("Graph");
		options.registerOptions(toolOptions, null);
		options.initializeFromOptions(tool);

		AttributedVertex vertex = new AttributedVertex("Foo");
		vertex.setVertexType("V1");
		assertEquals(Color.BLUE, options.getVertexColor(vertex));

		Options graphDisplayOptions = toolOptions.getOptions(options.getRootOptionsName());
		Options vertexColorOptions = graphDisplayOptions.getOptions("Vertex Colors");
		vertexColorOptions.setColor("V1", Color.CYAN);

		assertEquals(Color.CYAN, options.getVertexColor(vertex));
	}

}
