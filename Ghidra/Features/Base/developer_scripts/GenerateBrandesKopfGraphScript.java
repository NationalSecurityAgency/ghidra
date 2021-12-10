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
 * Script to generate graph to test BrandesKopf algorithm
 */
public class GenerateBrandesKopfGraphScript extends GhidraScript {
	private AttributedGraph graph = new AttributedGraph("test", new EmptyGraphType());
	private int nextEdgeID = 1;

	@Override
	protected void run() throws Exception {
		PluginTool tool = getState().getTool();
		GraphDisplayBroker service = tool.getService(GraphDisplayBroker.class);
		GraphDisplay display = service.getDefaultGraphDisplay(false, monitor);
		generateGraph();
		display.setGraph(graph, "Test2", false, monitor);
	}


	private void generateGraph() {

		AttributedVertex[] list = new AttributedVertex[24];
		int i=1;
		list[i++] = vertex("1");
		list[i++] = vertex("2");
		list[i++] = vertex("3");
		list[i++] = vertex("4");
		list[i++] = vertex("5");
		list[i++] = vertex("6");
		list[i++] = vertex("7");
		list[i++] = vertex("8");
		list[i++] = vertex("9");
		list[i++] = vertex("10");
		list[i++] = vertex("11");
		list[i++] = vertex("12");
		list[i++] = vertex("13");
		list[i++] = vertex("14");
		list[i++] = vertex("15");
		list[i++] = vertex("16");
		list[i++] = vertex("17");
		list[i++] = vertex("18");
		list[i++] = vertex("19");
		list[i++] = vertex("20");
		list[i++] = vertex("21");
		list[i++] = vertex("22");
		list[i++] = vertex("23");

		edge(list[1], list[3]);
		edge(list[1], list[4]);
		edge(list[1], list[13]);
		edge(list[1], list[21]);

		edge(list[2], list[3]);
		edge(list[2], list[20]);

		edge(list[3], list[4]);
		edge(list[3], list[5]);
		edge(list[3], list[23]);

		edge(list[4], list[6]);

		edge(list[5], list[7]);

		edge(list[6], list[8]);
		edge(list[6], list[16]);
		edge(list[6], list[23]);

		edge(list[7], list[9]);

		edge(list[8], list[10]);
		edge(list[8], list[11]);

		edge(list[9], list[12]);

		edge(list[10], list[13]);
		edge(list[10], list[14]);
		edge(list[10], list[15]);

		edge(list[11], list[15]);
		edge(list[11], list[16]);

		edge(list[12], list[20]);

		edge(list[13], list[17]);

		edge(list[14], list[17]);
		edge(list[14], list[18]);
		// no 15 targets

		edge(list[16], list[18]);
		edge(list[16], list[19]);
		edge(list[16], list[20]);

		edge(list[18], list[21]);

		edge(list[19], list[22]);

		edge(list[21], list[23]);

		edge(list[22], list[23]);

	}

	private AttributedVertex vertex(String name) {
		return graph.addVertex(name, name);
	}


	private AttributedEdge edge(AttributedVertex v1, AttributedVertex v2) {
		return graph.addEdge(v1, v2);
	}

}
