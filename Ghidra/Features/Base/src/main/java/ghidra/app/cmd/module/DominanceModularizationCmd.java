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
package ghidra.app.cmd.module;

import java.util.Collection;
import java.util.Set;

import ghidra.graph.*;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.util.GroupPath;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.CancelledException;

/**
 * this code will apply the Dominance algorithm to a module or fragment in
 * a program tree.  First the code generates a call graph and from there a
 * dominance graph and finally a dominance structure in the program tree.
 */
public class DominanceModularizationCmd extends AbstractModularizationCmd {

	public DominanceModularizationCmd(GroupPath path, String treeName, ProgramSelection selection,
			CodeBlockModel blockModel) {
		super("Dominance", path, treeName, selection, blockModel);
	}

	@Override
	protected void applyModel() throws CancelledException {
		GDirectedGraph<CodeBlockVertex, CodeBlockEdge> callGraph = createCallGraph();
		CodeBlockVertex root = createRoot(callGraph, "Dominance");

		GDirectedGraph<CodeBlockVertex, GEdge<CodeBlockVertex>> dominanceGraph =
			GraphAlgorithms.findDominanceTree(callGraph, monitor);

		rebuildProgramTree(dominanceGraph, root, destinationModule);
	}

	private CodeBlockVertex createRoot(GDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph,
			String name) {

		Set<CodeBlockVertex> entryPoints = GraphAlgorithms.getEntryPoints(graph);
		if (entryPoints.size() == 1) {
			return entryPoints.iterator().next();
		}

		CodeBlockVertex nexus = new CodeBlockVertex(name);
		graph.addVertex(nexus);

		for (CodeBlockVertex entry : entryPoints) {
			CodeBlockEdge e = new CodeBlockEdge(nexus, entry);
			graph.addEdge(e);
		}
		return nexus;
	}

	private void rebuildProgramTree(GDirectedGraph<CodeBlockVertex, GEdge<CodeBlockVertex>> dg,
			CodeBlockVertex vertex, ProgramModule module) throws CancelledException {

		Collection<CodeBlockVertex> children = dg.getSuccessors(vertex);
		if (children == null || children.isEmpty()) {
			makeFragment(program, module, vertex);
			return;
		}

		ProgramModule currentModule = createModule(module, vertex.getName());
		makeFragment(program, currentModule, vertex);

		for (CodeBlockVertex child : children) {
			monitor.checkCanceled();
			rebuildProgramTree(dg, child, currentModule);
		}
	}
}
