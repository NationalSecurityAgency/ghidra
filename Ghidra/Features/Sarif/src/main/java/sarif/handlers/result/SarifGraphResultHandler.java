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
package sarif.handlers.result;

import java.util.*;
import java.util.Map.Entry;

import com.contrastsecurity.sarif.*;

import ghidra.program.model.address.Address;
import ghidra.service.graph.*;
import sarif.handlers.SarifResultHandler;

public class SarifGraphResultHandler extends SarifResultHandler {

	@Override
	public String getKey() {
		return "Graphs";
	}

	@Override
	public List<AttributedGraph> parse() {
		List<AttributedGraph> res = new ArrayList<AttributedGraph>();
		Set<Graph> graphs = result.getGraphs();
		if (graphs != null) {
			for (Graph g : graphs) {
				res.add(parseGraph(g));
			}
		}
		return res;
	}

	private AttributedGraph parseGraph(Graph g) {
		AttributedGraph graph =
			new AttributedGraph(controller.getProgram().getDescription(), new EmptyGraphType());
		Map<String, AttributedVertex> nodeMap = new HashMap<String, AttributedVertex>();
		for (Node n : g.getNodes()) {
			Address addr = controller.locationToAddress(run, n.getLocation());
			String text = n.getLabel().getText();
			AttributedVertex vertex = graph.addVertex(n.getId(), addr.toString());
			PropertyBag properties = n.getProperties();
			if (properties != null) {
				Map<String, Object> additional = properties.getAdditionalProperties();
				if (additional != null) {
					for (Entry<String, Object> entry : additional.entrySet()) {
						vertex.setAttribute(entry.getKey(), entry.getValue().toString());
					}
				}
			}
			vertex.setAttribute("Label", text);
			vertex.setAttribute("Address", addr.toString(true));
			nodeMap.put(n.getId(), vertex);
		}
		for (Edge e : g.getEdges()) {
			graph.addEdge(nodeMap.get(e.getSourceNodeId()), nodeMap.get(e.getTargetNodeId()));
		}
		return graph;
	}
}
