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

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeNode;

/**
 * 
 * An object of this class is a root node in a tree of instruction 
 * sequences.
 *
 */

public class FunctionBitPatternsGTreeRootNode extends GTreeNode {

	@Override
	public String getName() {
		return "root node";
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return null;
	}

	@Override
	public String getToolTip() {
		return null;
	}

	/**
	 * Recursively sort the children of this node
	 */
	public void sort() {
		for (GTreeNode node : getChildren()) {
			((FunctionBitPatternsGTreeNode) node).sortAndSetFields();
		}
		List<GTreeNode> children = new ArrayList<>(getChildren());
		Collections.sort(children);
		setChildren(children);
	}

	/**
	 * Recursively apply a {@link PercentageFilter} to all of the nodes in the tree
	 * @param filter filter to apply
	 */
	public void filterByPercentage(PercentageFilter filter) {
		for (GTreeNode node : getChildren()) {
			FunctionBitPatternsGTreeNode fspNode = (FunctionBitPatternsGTreeNode) node;
			if (filter.allows(fspNode.getPercentage())) {
				fspNode.filterByPercentage(filter);
			}
			else {
				removeNode(fspNode);
			}
		}
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

}
