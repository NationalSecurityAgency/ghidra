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

import java.util.*;
import java.util.Map.Entry;

import com.contrastsecurity.sarif.*;

import ghidra.program.model.address.Address;
import ghidra.service.graph.*;
import sarif.handlers.SarifRunHandler;
import sarif.model.SarifDataFrame;

public class SarifGraphRunHandler extends SarifRunHandler {

	@Override
	public String getKey() {
		return "graphs";
	}

	@Override
	public boolean isEnabled(SarifDataFrame dframe) {
		return dframe.getController().getDefaultGraphHander().equals(getClass());
	}

	@Override
	public List<AttributedGraph> parse() {
		List<AttributedGraph> res = new ArrayList<>();
		Set<Graph> graphs = run.getGraphs();
		if (graphs != null) {
			for (Graph g : graphs) {
				String description =
					g.getDescription() == null ? controller.getProgram().getDescription()
							: g.getDescription().getText();
				AttributedGraph graph = new AttributedGraph(description, new EmptyGraphType());
				Map<String, AttributedVertex> nodeMap = new HashMap<String, AttributedVertex>();
				for (Node n : g.getNodes()) {
					AttributedVertex vertex = graph.addVertex(n.getId(), n.getId());
					populateVertex(n, vertex);
					nodeMap.put(n.getId(), vertex);
				}
				for (Edge e : g.getEdges()) {
					graph.addEdge(nodeMap.get(e.getSourceNodeId()),
						nodeMap.get(e.getTargetNodeId()));
				}
				res.add(graph);
			}
		}
		return res;
	}

	protected void populateVertex(Node n, AttributedVertex vertex) {
		Address addr = controller.locationToAddress(run, n.getLocation());
		vertex.setName(addr.toString());
		String text = n.getLabel().getText();
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
