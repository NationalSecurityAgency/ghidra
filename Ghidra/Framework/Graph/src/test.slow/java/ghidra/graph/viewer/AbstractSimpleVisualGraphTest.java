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
package ghidra.graph.viewer;

import ghidra.graph.graphs.*;
import ghidra.graph.support.TestVisualGraph;
import ghidra.graph.support.TextAreaTestVertex;

/**
 * A version of the {@link AbstractVisualGraphTest} that creates a simple graph (this class 
 * may not be needed, but the hope is that more default state can be recorded here)
 */
public abstract class AbstractSimpleVisualGraphTest extends AbstractVisualGraphTest {

	@Override
	protected TestVisualGraph buildGraph() {

		TestVisualGraph g = new TestVisualGraph();

		AbstractTestVertex v1 = new LabelTestVertex("1");
		AbstractTestVertex v2 = new LabelTestVertex("2");
		AbstractTestVertex v3 = new LabelTestVertex("3");
		TextAreaTestVertex textAreaVertex = new TextAreaTestVertex("Text Area vertex...");
		TestEdge e1 = new TestEdge(v1, v2);
		TestEdge e2 = new TestEdge(v2, v3);
		TestEdge e3 = new TestEdge(v1, textAreaVertex);

		g.addVertex(v1);
		g.addVertex(v2);
		g.addVertex(v3);
		g.addVertex(textAreaVertex);
		g.addEdge(e1);
		g.addEdge(e2);
		g.addEdge(e3);

		return g;
	}

}
