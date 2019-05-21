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
package ghidra.graph.support;

import java.util.Collection;

import ghidra.graph.graphs.*;

/**
 * A visual graph implementation used for testing.
 */
public class TestVisualGraph extends DefaultVisualGraph<AbstractTestVertex, TestEdge> {

	private TestGraphLayout layout;

	@Override
	public TestGraphLayout getLayout() {
		return layout;
	}

	public void setLayout(TestGraphLayout layout) {
		this.layout = layout;
	}

	@Override
	public DefaultVisualGraph<AbstractTestVertex, TestEdge> copy() {

		TestVisualGraph newGraph = new TestVisualGraph();

		Collection<AbstractTestVertex> myVertices = getVertices();
		for (AbstractTestVertex v : myVertices) {
			newGraph.addVertex(v);
		}

		Collection<TestEdge> myEdges = getEdges();
		for (TestEdge e : myEdges) {
			newGraph.addEdge(e);
		}

		newGraph.setLayout(layout);

		return newGraph;
	}
}
