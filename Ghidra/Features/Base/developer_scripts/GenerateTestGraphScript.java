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
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.*;

/**
 * Sample script to test graph service
 */
public class GenerateTestGraphScript extends GhidraScript {
	private AttributedGraph graph = new AttributedGraph("Test", new EmptyGraphType());
	private int nextEdgeID = 1;

	@Override
	protected void run() throws Exception {
		PluginTool tool = getState().getTool();
		GraphDisplayBroker service = tool.getService(GraphDisplayBroker.class);
		GraphDisplay display = service.getDefaultGraphDisplay(false, monitor);
		generateGraph();
		display.setGraph(graph, "Test", false, monitor);
	}

	private void generateGraph() {

		AttributedVertex A = vertex("A");
		AttributedVertex B = vertex("B");
		AttributedVertex C = vertex("C");
		AttributedVertex D = vertex("D");

		edge(A, B);
		edge(A, C);
		edge(B, D);
		edge(C, D);
		edge(D, A);
	}

	private AttributedVertex vertex(String name) {
		return graph.addVertex(name, name);
	}

	private AttributedEdge edge(AttributedVertex v1, AttributedVertex v2) {
		return graph.addEdge(v1, v2);
	}


}
