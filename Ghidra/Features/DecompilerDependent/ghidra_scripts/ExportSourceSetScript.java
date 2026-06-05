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
//Decompile the function at the cursor and its callees, then output facts files corresponding to the pcodes
//@category PCode

import java.io.*;
import java.util.*;

import com.contrastsecurity.sarif.LogicalLocation;

import ghidra.app.plugin.core.decompiler.taint.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.*;
import ghidra.graph.jung.JungDirectedGraph;
import ghidra.service.graph.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.GraphException;
import sarif.SarifUtils;


public class ExportSourceSetScript extends GhidraScript {

	private TaintPlugin plugin;
	private TaintProvider provider;
	private TaintOptions options;
	Map<String, AttributedVertex> nodeMap = new HashMap<String, AttributedVertex>();
	private Map<String, String> mnemonics = new HashMap<>();

	@Override
	protected void run() {

		PluginTool tool = state.getTool();
		if (tool == null) {
			println("Script is not running in GUI");
		}
		plugin = (TaintPlugin) tool.getService(TaintService.class);
		provider = plugin.getProvider();
		options = plugin.getOptions();
		String facts = options.getTaintFactsDirectory();
		File mnFile = new File(facts+"/PCODE_MNEMONIC.facts");
		try {
			BufferedReader reader = new BufferedReader(new FileReader(mnFile));
			String line = null;
			while ((line = reader.readLine()) != null) {
				String[] split = line.split("\t");
				mnemonics.put(split[0], split[1]);
			}
			reader.close();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		
		AttributedGraph g = handle();
		showGraph(g);
	}

	public GDirectedGraph<AttributedVertex, GEdge<AttributedVertex>> parse() {
		GDirectedGraph<AttributedVertex, GEdge<AttributedVertex>> graph = new JungDirectedGraph<>();
		Map<String, Set<String>> edgeMap = SarifUtils.getEdgeMap();
		for (Set<String> ids :  edgeMap.values()) {
			for (String id : ids) {
				String srcId = SarifUtils.getEdgeSource(id);
				String dstId = SarifUtils.getEdgeDest(id);
				String mnemonic = mnemonics.get(id.split("/")[2]);
				if (mnemonic != null && !mnemonic.equals("INDIRECT")) {
					AttributedVertex s = addVertex(srcId, id);
					AttributedVertex d = addVertex(dstId, id);
					graph.addVertex(s);
					graph.addVertex(d);
					graph.addEdge(new DefaultGEdge<>(s,d));
				}
			}
		}
		return graph;
	}
	
	private AttributedVertex addVertex(String id, String edgeId) {
		LogicalLocation[] locs = SarifUtils.getNodeLocs(id);
		String label = locs.length == 0 ? id : locs[0].getFullyQualifiedName();
		AttributedVertex v = new AttributedVertex(label);
		v.setAttribute("id", id);
		v.setAttribute("edge", edgeId);
		nodeMap.put(id, v);
		return v;
	}

	public AttributedGraph handle() {
		GDirectedGraph<AttributedVertex, GEdge<AttributedVertex>> g = parse();
		Collection<AttributedVertex> vertices = g.getVertices();
		Map<AttributedVertex, AttributedVertex> toFrom = new HashMap<>();
		Collection<GEdge<AttributedVertex>> edges = g.getEdges();
		for (GEdge<AttributedVertex> edge : edges) {
			AttributedVertex end = edge.getEnd();
			AttributedVertex start = edge.getStart();
			toFrom.put(end, start);
		}
		Set<AttributedVertex> sources = new HashSet<>();
		Set<AttributedVertex> nonSources = new HashSet<>();
		Set<Set<AttributedVertex>> components = GraphAlgorithms.getStronglyConnectedComponents(g);
		for (Set<AttributedVertex> c : components) {
			Iterator<AttributedVertex> iterator = c.iterator();
			boolean isSource = true;
			while (iterator.hasNext()) {
				AttributedVertex to = iterator.next();
				AttributedVertex from = toFrom.get(to);
				if (from != null && !c.contains(from)) {
					isSource = false;
					break;
				}
			}
			if (isSource) {
				sources.addAll(c);
			}
			else {
				nonSources.addAll(c);
			}
		}
		for (AttributedVertex v : vertices) {
			if (!nonSources.contains(v)) {
				AttributedVertex from = toFrom.get(v);
				if (from == null) {
					sources.add(v);
				}
				else {
					nonSources.add(v);
				}
			}
		}

		List<String> srcList = new ArrayList<>();
		AttributedGraph graph = new AttributedGraph("BOB", new EmptyGraphType());
		for (GEdge<AttributedVertex> edge : edges) {
			AttributedVertex end = edge.getEnd();
			AttributedVertex start = edge.getStart();
			String edgeId = end.getAttribute("edge");
			String edgeDesc = edgeId.split("/")[2];
			String mnemonic = mnemonics.get(edgeDesc);

			AttributedEdge ae = graph.addEdge(start, end);
			ae.setAttribute("desc", edgeId);
			ae.setAttribute("mnemonic", mnemonic);
			start.setAttribute("src", sources.contains(start) ? "TRUE" : "FALSE");
			graph.addVertex(start);
			end.setAttribute("src", sources.contains(end) ? "TRUE" : "FALSE");
			graph.addVertex(end);
			if (sources.contains(start) && !start.getName().contains(":const:")) {
				srcList.add(edgeDesc+"::"+start.getName());
			}
		}
		String outfile = options.getTaintOutputDirectory();
		File srcFile = new File(outfile+"/SOURCES");
		try {
			BufferedWriter srcWriter = new BufferedWriter(new FileWriter(srcFile));
			for (String src : srcList) {
				srcWriter.write(src+"\n");
			}
			srcWriter.close();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		
		return graph;
	}
	
	public void showGraph(AttributedGraph graph) {
		try {
			PluginTool tool = plugin.getTool();
			GraphDisplayBroker service = tool.getService(GraphDisplayBroker.class);
			GraphDisplay display = service.getDefaultGraphDisplay(false, null);
			GraphDisplayOptions graphOptions = new GraphDisplayOptions(new EmptyGraphType());
			graphOptions.setMaxNodeCount(10000);
			display.setGraph(graph, graphOptions, graph.getDescription(), false, null);
		}
		catch (GraphException | CancelledException e) {
			Msg.error(this, "showGraph failed " + e.getMessage());
		}
	}

}
