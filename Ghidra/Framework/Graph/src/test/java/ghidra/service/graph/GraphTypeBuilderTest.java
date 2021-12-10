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

import java.util.List;

import org.junit.Test;

public class GraphTypeBuilderTest {

	@Test
	public void testName() {
		GraphType graphType = new GraphTypeBuilder("Test").build();
		assertEquals("Test", graphType.getName());
	}

	@Test
	public void testDescription() {
		GraphType graphType = new GraphTypeBuilder("Test")
				.description("abc")
				.build();
		assertEquals("abc", graphType.getDescription());
	}

	@Test
	public void testNoDescriptionUsesName() {
		GraphType graphType = new GraphTypeBuilder("Test").build();
		assertEquals("Test", graphType.getDescription());
	}

	@Test
	public void testVertexType() {
		GraphType graphType = new GraphTypeBuilder("Test")
				.vertexType("V1")
				.vertexType("V2")
				.build();

		List<String> vertexTypes = graphType.getVertexTypes();
		assertEquals(2, vertexTypes.size());
		assertEquals("V1", vertexTypes.get(0));
		assertEquals("V2", vertexTypes.get(1));
	}

	@Test
	public void testEdgeType() {
		GraphType graphType = new GraphTypeBuilder("Test")
				.edgeType("E1")
				.edgeType("E2")
				.build();

		List<String> edgeTypes = graphType.getEdgeTypes();
		assertEquals(2, edgeTypes.size());
		assertEquals("E1", edgeTypes.get(0));
		assertEquals("E2", edgeTypes.get(1));
	}
}
