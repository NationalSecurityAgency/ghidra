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

import java.util.*;

import ghidra.graph.GDirectedGraph;
import ghidra.graph.GraphAlgorithms;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.listing.ProgramModule;
import ghidra.program.util.GroupPath;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.CancelledException;

/**
 * This command will organize a program tree into levels from the bottom up.  In other words, all
 * the leaf functions are at the same level and all the functions that only call leaf functions are
 * one level less and so on and so forth.
 */
public class ComplexityDepthModularizationCmd extends AbstractModularizationCmd {

	public ComplexityDepthModularizationCmd(GroupPath path, String treeName,
			ProgramSelection selection, CodeBlockModel blockModel) {
		super("Complexity Depth", path, treeName, selection, blockModel);
	}

	@Override
	protected void applyModel() throws CancelledException {
		GDirectedGraph<CodeBlockVertex, CodeBlockEdge> callGraph = createCallGraph();

		Map<CodeBlockVertex, Integer> complexityDepth =
			GraphAlgorithms.getComplexityDepth(callGraph);

		rebuildProgramTree(complexityDepth);
	}

	private void rebuildProgramTree(Map<CodeBlockVertex, Integer> levelMap)
			throws CancelledException {
		List<List<CodeBlockVertex>> partition = partitionVerticesByReverseLevel(levelMap);

		for (int i = 0; i < partition.size(); i++) {
			List<CodeBlockVertex> list = partition.get(i);
			ProgramModule levelModule = createModule(destinationModule, "Level " + i);
			for (CodeBlockVertex v : list) {
				monitor.checkCanceled();
				makeFragment(program, levelModule, v);
			}
		}
	}

	private List<List<CodeBlockVertex>> partitionVerticesByReverseLevel(
			Map<CodeBlockVertex, Integer> levelMap) {
		List<List<CodeBlockVertex>> levelList = new ArrayList<>();
		int maxLevel = getMaxLevel(levelMap);
		for (int i = 0; i <= maxLevel; i++) {
			levelList.add(new ArrayList<CodeBlockVertex>());
		}
		for (CodeBlockVertex v : levelMap.keySet()) {
			int reverseLevel = maxLevel - levelMap.get(v);
			levelList.get(reverseLevel).add(v);
		}
		for (List<CodeBlockVertex> list : levelList) {
			Collections.sort(list);
		}
		return levelList;
	}

	private int getMaxLevel(Map<CodeBlockVertex, Integer> levelMap) {
		int maxLevel = -1;
		for (Integer level : levelMap.values()) {
			if (level > maxLevel) {
				maxLevel = level;
			}
		}
		return maxLevel;
	}

}
