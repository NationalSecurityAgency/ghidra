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
import java.awt.Font;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.theme.*;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.util.HelpLocation;

public class GraphDisplayOptionsTest {

	private GraphType graphType;
	private GraphDisplayOptions options;

	@Before
	public void setUp() {
		// create a dummy theme manager that defines values for use in this test
		DummyThemeManager themeManager = new DummyThemeManager();

		// create a new graph definition and options using theme properties
		List<String> vertexTypes = Arrays.asList("V1", "V2", "V3");
		List<String> edgeTypes = Arrays.asList("E1", "E2", "E3");
		graphType = new GraphType("Test", "Test Description", vertexTypes, edgeTypes);
		options = new GraphDisplayOptions(graphType);
		options.setVertexColor("V1", "color.V1");
		options.setVertexColor("V2", "color.V2");
		options.setVertexColor("V3", "color.V3");
		options.setEdgeColor("E1", "color.E1");
		options.setEdgeColor("E2", "color.E2");
		options.setEdgeColor("E3", "color.E3");
		options.setDefaultEdgeColor("color.edge.default");
		options.setDefaultVertexColor("color.vertex.default");
		options.setEdgeSelectionColor("color.edge.selected");
		options.setVertexSelectionColor("color.vertex.selected");
		options.setFont("font.graph");

	}

	@Test
	public void testSetAndGetDefaultVertexShape() {
		options.setDefaultVertexShape(VertexShape.STAR);
		assertEquals(VertexShape.STAR, options.getDefaultVertexShape());
	}

	@Test
	public void testSetAndGetDefaultVertexColor() {
		options.setDefaultVertexColor(Palette.RED);
		assertEquals(Palette.RED, options.getDefaultVertexColor());
	}

	@Test
	public void testSetAndGetDefaultEdgeColor() {
		options.setDefaultEdgeColor(Palette.RED);
		assertEquals(Palette.RED, options.getDefaultEdgeColor());
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
		options.setVertexColor("V1", Palette.RED);
		options.setVertexColor("V2", Palette.GREEN);
		AttributedVertex vertex = new AttributedVertex("Foo");

		assertEquals(options.getDefaultVertexColor(), options.getVertexColor(vertex));

		vertex.setVertexType("V1");
		assertEquals(Palette.RED, options.getVertexColor(vertex));

		vertex.setVertexType("V2");
		assertEquals(Palette.GREEN, options.getVertexColor(vertex));
	}

	@Test
	public void testGetVertexColorWithOverride() {
		options.setVertexColor("V1", Palette.RED);
		options.setVertexColor("V2", Palette.GREEN);
		options.setVertexColorOverrideAttributeKey("Color");
		AttributedVertex vertex = new AttributedVertex("Foo");

		vertex.setVertexType("V1");
		assertEquals(Palette.RED, options.getVertexColor(vertex));

		vertex.setAttribute("Color", Palette.BLUE.toString());

		assertEquals(Palette.BLUE.getRGB(), options.getVertexColor(vertex).getRGB());
	}

	@Test
	public void testGetEdgeColor() {
		options.setEdgeColor("E1", Palette.RED);
		options.setEdgeColor("E2", Palette.GREEN);
		AttributedEdge edge = new AttributedEdge("1");
		assertEquals(options.getDefaultEdgeColor(), options.getEdgeColor(edge));

		edge.setEdgeType("E1");
		assertEquals(Palette.RED, options.getEdgeColor(edge));

		edge.setEdgeType("E2");
		assertEquals(Palette.GREEN, options.getEdgeColor(edge));
	}

	@Test
	public void testGetEdgeColorWithOverride() {
		options.setEdgeColor("E1", Palette.RED);
		options.setEdgeColor("E2", Palette.GREEN);
		options.setEdgeColorOverrideAttributeKey("Color");
		AttributedEdge edge = new AttributedEdge("1");
		assertEquals(options.getDefaultEdgeColor(), options.getEdgeColor(edge));

		edge.setEdgeType("E1");
		assertEquals(Palette.RED, options.getEdgeColor(edge));

		edge.setAttribute("Color", Palette.BLUE.toString());

		assertEquals(Palette.BLUE.getRGB(), options.getEdgeColor(edge).getRGB());
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
		assertEquals(options.getDefaultVertexColor().getRGB(),
			options.getVertexColor("V1").getRGB());
		options.setVertexColor("V1", Palette.RED);
		assertEquals(Palette.RED.getRGB(), options.getVertexColor("V1").getRGB());
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
		options.setEdgeColor("E1", Palette.RED);
		assertEquals(Palette.RED, options.getEdgeColor("E1"));
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
		assertEquals(options.getDefaultVertexColor().getRGB(),
			vertexColorOptions.getColor("V1", Palette.BLACK).getRGB());

		Options vertexShapeOptions = graphDisplayOptions.getOptions("Vertex Shapes");
		leafOptionNames = vertexShapeOptions.getLeafOptionNames();
		assertEquals(Arrays.asList("V1", "V2", "V3"), leafOptionNames);
		assertEquals(options.getDefaultVertexShape().getName(),
			vertexShapeOptions.getString("V1", "Bob"));

		Options edgeColorOptions = graphDisplayOptions.getOptions("Edge Colors");
		leafOptionNames = edgeColorOptions.getLeafOptionNames();
		assertEquals(Arrays.asList("E1", "E2", "E3"), leafOptionNames);
		assertEquals(options.getDefaultEdgeColor().getRGB(),
			edgeColorOptions.getColor("E1", Palette.WHITE).getRGB());

		Options miscellaneousOptions = graphDisplayOptions.getOptions("Miscellaneous");
		leafOptionNames = miscellaneousOptions.getLeafOptionNames();
		assertEquals(Arrays.asList("Use Icons", "Max Graph Size",
			"Selected Vertex Color", "Default Layout Algorithm", "Default Vertex Color",
			"Default Vertex Shape", "Selected Edge Color", "Label Position",
			"Default Edge Color", "Font", "Favored Edge Type"), leafOptionNames);

	}

	// Create a ThemeManager that it not fully initialized for speed. This class provides
	// fake property theme values.
	class DummyThemeManager extends StubThemeManager {
		DummyThemeManager() {
			installTestValues();
			installExpectedValues();
			installInGui();
		}

		private void installExpectedValues() {
			setColor(new ColorValue("color.vertex.selected", Color.BLACK));
			setColor(new ColorValue("color.edge.selected", Color.BLACK));
			setColor(new ColorValue("color.graphdisplay.vertex.default", Color.BLACK));
			setColor(new ColorValue("color.graphdisplay.edge.default", Color.BLACK));
			setFont(new FontValue("font.graph", new Font("monospaced", Font.PLAIN, 12)));

		}

		protected void installTestValues() {
			setColor(new ColorValue("color.V1", Color.BLACK));
			setColor(new ColorValue("color.V2", Color.BLACK));
			setColor(new ColorValue("color.V3", Color.BLACK));
			setColor(new ColorValue("color.E1", Color.BLACK));
			setColor(new ColorValue("color.E2", Color.BLACK));
			setColor(new ColorValue("color.E3", Color.BLACK));
			setColor(new ColorValue("color.edge.default", Color.BLACK));
			setColor(new ColorValue("color.vertex.default", Color.BLACK));
			setColor(new ColorValue("color.edge.selected", Color.BLACK));
			setColor(new ColorValue("color.vertex.selected", Color.BLACK));
			setColor(new ColorValue("color.graphdisplay.vertex.selected", Color.BLACK));
			setColor(new ColorValue("color.graphdisplay.edge.selected", Color.BLACK));
			setColor(new ColorValue("color.vertex.selected", Color.BLACK));
			setColor(new ColorValue("color.vertex.selected", Color.BLACK));

			setFont(new FontValue("font.graph", new Font("monospaced", Font.PLAIN, 12)));
			setFont(
				new FontValue("font.graphdisplay.default", new Font("monospaced", Font.PLAIN, 12)));
		}

	}
}
