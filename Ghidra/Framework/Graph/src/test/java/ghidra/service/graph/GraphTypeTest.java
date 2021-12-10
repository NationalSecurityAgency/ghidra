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

import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

public class GraphTypeTest {
	private GraphType graphType;

	@Before
	public void setUp() {
		List<String> vertexTypes = Arrays.asList("V1", "V2", "V3" );
		List<String> edgeTypes = Arrays.asList("E1", "E2", "E3" );
		graphType = new GraphType("Test", "Test Description", vertexTypes, edgeTypes);
		
	}

	@Test
	public void testName() {
		assertEquals("Test", graphType.getName());
	}

	@Test
	public void testDescription() {
		assertEquals("Test Description", graphType.getDescription());
	}

	@Test
	public void testGetVertexTypes() {
		List<String> types = graphType.getVertexTypes();
		assertEquals(3, types.size());
		assertEquals("V1", types.get(0));
		assertEquals("V2", types.get(1));
		assertEquals("V3", types.get(2));
	}

	@Test
	public void testGetEdgeTypes() {
		List<String> types = graphType.getEdgeTypes();
		assertEquals(3, types.size());
		assertEquals("E1", types.get(0));
		assertEquals("E2", types.get(1));
		assertEquals("E3", types.get(2));
	}

	@Test
	public void testContainsVertexType() {
		assertTrue(graphType.containsVertexType("V1"));
		assertTrue(graphType.containsVertexType("V2"));
		assertTrue(graphType.containsVertexType("V3"));
		assertFalse(graphType.containsVertexType("E1"));
	}

	@Test
	public void testContainsEdgeType() {
		assertTrue(graphType.containsEdgeType("E1"));
		assertTrue(graphType.containsEdgeType("E2"));
		assertTrue(graphType.containsEdgeType("E3"));
		assertFalse(graphType.containsEdgeType("V2"));
	}
}
