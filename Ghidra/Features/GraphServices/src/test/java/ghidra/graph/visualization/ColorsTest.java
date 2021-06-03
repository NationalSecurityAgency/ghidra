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
package ghidra.graph.visualization;

import static org.junit.Assert.*;

import java.awt.Color;

import org.junit.Test;

import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;

public class ColorsTest {
	@Test
	public void testParseHashHexColor() {
		Color hexColor = Colors.getHexColor("#ff0000");
		assertEquals(Color.RED, hexColor);
	}

	@Test
	public void testParseHexColor() {
		Color hexColor = Colors.getHexColor("0xff0000");
		assertEquals(Color.RED, hexColor);
	}

	@Test
	public void testGetColorFromVertexType() {
		AttributedVertex vertex = new AttributedVertex("A");
		vertex.setAttribute("VertexType", "Exit");
		vertex.setAttribute("Color", "0xffffff");
		assertEquals(Color.MAGENTA, Colors.getColor(vertex));
	}

	@Test
	public void testGetColorFromVertexNoVertexType() {
		AttributedVertex vertex = new AttributedVertex("A");
		vertex.setAttribute("Color", "0xffffff");
		assertEquals(Color.WHITE, Colors.getColor(vertex));
	}

	@Test
	public void testGetColorFromVertexNoAttributes() {
		AttributedVertex vertex = new AttributedVertex("A");
		assertEquals(Color.GREEN, Colors.getColor(vertex));
	}

	@Test
	public void testGetColorFromEdgeType() {
		AttributedEdge edge = new AttributedEdge("A");
		edge.setAttribute("EdgeType", "Computed");
		edge.setAttribute("Color", "0xffffff");
		assertEquals(Color.CYAN, Colors.getColor(edge));
	}

	@Test
	public void testGetColorFromEdgeNoEdgeType() {
		AttributedEdge edge = new AttributedEdge("A");
		edge.setAttribute("Color", "0xffffff");
		assertEquals(Color.WHITE, Colors.getColor(edge));
	}
}
