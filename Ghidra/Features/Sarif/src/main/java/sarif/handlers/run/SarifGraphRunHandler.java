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
package sarif.handlers.run;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.contrastsecurity.sarif.Edge;
import com.contrastsecurity.sarif.Graph;
import com.contrastsecurity.sarif.Node;
import com.contrastsecurity.sarif.Run;

import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.EmptyGraphType;
import sarif.handlers.SarifRunHandler;
import sarif.model.SarifDataFrame;

public class SarifGraphRunHandler extends SarifRunHandler {

	@Override
	public String getKey() {
		return "graphs";
	}

	@Override
	public List<AttributedGraph> parse() {
		List<AttributedGraph> res = new ArrayList<>();
		Set<Graph> graphs = run.getGraphs();
		if (graphs != null) {
			for (Graph g : graphs) {
				String description = g.getDescription() == null ? controller.getProgram().getDescription()
						: g.getDescription().getText();
				AttributedGraph graph = new AttributedGraph(description, new EmptyGraphType());
				Map<String, AttributedVertex> nodeMap = new HashMap<String, AttributedVertex>();
				for (Node n : g.getNodes()) {
					nodeMap.put(n.getId(), graph.addVertex(n.getId(), n.getLabel().getText()));
				}
				for (Edge e : g.getEdges()) {
					graph.addEdge(nodeMap.get(e.getSourceNodeId()), nodeMap.get(e.getTargetNodeId()));
				}
				res.add(graph);
			}
		}
		return res;
	}

	@Override
	public void handle(SarifDataFrame df, Run run) {
		this.df = df;
		this.controller = df.getController();
		this.run = run;
		List<AttributedGraph> res = parse();
		if (res != null) {
			for (AttributedGraph g : res) {
				controller.showGraph(g);
			}
		}
	}
}
