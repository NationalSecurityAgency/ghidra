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
package ghidra.bitpatterns.info;

import java.util.*;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;

/**
 * 
 * A {@link GTree} extended with a count.  The count represents the total number 
 * of instruction sequences represented in the tree.
 * 
 *
 */

public class FunctionBitPatternsGTree extends GTree {

	private int totalNum = 0;
	private PatternType type;

	/**
	 * Create a FunctionBitPatternsGTree for {@link PatternType} {@code type} with root node {@code root}
	 * @param root root node
	 * @param type {link PatternType} of instructions in tree
	 */
	public FunctionBitPatternsGTree(FunctionBitPatternsGTreeRootNode root, PatternType type) {
		super(root);
		this.type = type;
	}

	/**
	 * Get the total number of instructions sequences that make up the tree
	 * @return number of sequences
	 */
	public int getTotalNum() {
		return totalNum;
	}

	/**
	 * Get the pattern type of the instructions in the tree
	 * @return the patten type
	 */
	public PatternType getType() {
		return type;
	}

	/**
	 * Set the total number of instructions sequences in the tree
	 * @param totalNum
	 */
	public void setTotalNum(int totalNum) {
		this.totalNum = totalNum;
	}

	/**
	 * Creates a tree for a list of instructions of a certain type and applies a percentage filter.
	 * @param instSeqs {@link InstructionSequence}s which will make of the tree
	 * @param patternType {@link PatternType} of the instructions
	 * @param percentageFilter {@link PercentageFilter} to apply
	 * @return newly-created tree
	 */
	public static FunctionBitPatternsGTree createTree(List<InstructionSequence> instSeqs,
			PatternType patternType, PercentageFilter percentageFilter) {
		FunctionBitPatternsGTreeRootNode root = new FunctionBitPatternsGTreeRootNode();
		Map<GTreeNode, Map<String, GTreeNode>> nodeMap =
			new HashMap<GTreeNode, Map<String, GTreeNode>>();

		//for each node, want to find the children quickly instead of iterating through the 
		//list of children
		//need a map nodes - > keys -> nodes
		for (InstructionSequence currentSeq : instSeqs) {
			GTreeNode currentNode = root;
			int maxLevel = currentSeq.getInstructions().length;
			String[] currentInsts = currentSeq.getInstructions();
			for (int level = 0; level < maxLevel; level++) {
				StringBuilder keyBuilder = new StringBuilder();

				if (currentInsts[level] == null) {
					break;//out of instructions for this sequence
				}

				keyBuilder.append(currentSeq.getInstructions()[level]);
				keyBuilder.append(":");
				keyBuilder.append(Integer.toString(currentSeq.getSizes()[level]));
				String key = keyBuilder.toString();

				//make sure there is a map keys -> nodes for the current node
				Map<String, GTreeNode> currentNodeChildMap = nodeMap.get(currentNode);
				if (nodeMap.get(currentNode) == null) {
					currentNodeChildMap = new HashMap<String, GTreeNode>();
					nodeMap.put(currentNode, currentNodeChildMap);
				}
				//check if the current node has a child of the appropriate type
				//if it does: increment the count and proceed
				//otherwise: create a new node, and to map and set as a child
				GTreeNode currentNodeChild = currentNodeChildMap.get(key);
				if (currentNodeChild == null) {
					currentNodeChild = new FunctionBitPatternsGTreeNode(key,
						currentSeq.getInstructions()[level], currentSeq.getSizes()[level]);
					((FunctionBitPatternsGTreeNode) currentNodeChild).incrementCount(1);
					currentNodeChildMap.put(key, currentNodeChild);
					currentNode.addNode(currentNodeChild);
				}
				else {
					((FunctionBitPatternsGTreeNode) currentNodeChild).incrementCount(1);
				}
				currentNode = currentNodeChild;
			}
		}
		FunctionBitPatternsGTree tree = new FunctionBitPatternsGTree(root, patternType);
		tree.setTotalNum(instSeqs.size());
		root.sort();
		root.filterByPercentage(percentageFilter);
		return tree;
	}
}
