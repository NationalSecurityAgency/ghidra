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
import resources.ResourceManager;

/**
 * 
 * An object of this class represents a node in a tree of instruction sequences.
 *
 */
public class FunctionBitPatternsGTreeNode extends GTreeNode {

	private static final Icon DISABLED_ICON = ResourceManager.loadImage("images/ledred.png");

	private static final Icon ENABLED_ICON = ResourceManager.loadImage("images/ledgreen.png");

	private String name;
	private String instruction;
	private int numBytes;
	private int count;
	private boolean isLeaf;
	private double percentage;

	/**
	 * Creates a node in a {@link FunctionBitPatternsGTree}
	 * @param name name (key) of the node
	 * @param instruction name of instruction corresponding to this node
	 * @param numBytes number of bytes of the instruction
	 */
	public FunctionBitPatternsGTreeNode(String name, String instruction, Integer numBytes) {
		this.name = name;
		this.instruction = instruction;
		this.numBytes = numBytes;
		this.count = 0;
		this.getIcon(true);
		this.isLeaf = false;
	}

	/**
	 * Sort the children of this node by the number of instruction sequences passing through each one
	 * and set the percentage of all instruction sequences in the tree which pass through this node
	 */
	public void sortAndSetFields() {
		for (GTreeNode node : getChildren()) {
			((FunctionBitPatternsGTreeNode) node).sortAndSetFields();
		}
		List<GTreeNode> children = new ArrayList<>(getChildren());
		Collections.sort(children);
		setChildren(children);
		//now set isLeaf
		if (getChildren().isEmpty()) {
			isLeaf = true;
		}
		//set percentage of paths that go through this node
		//(the node must already be part of a FunctionStarPatternsGTree for this to make sense)
		if (this.getTree() == null) {
			percentage = 0.0;
		}
		else {
			percentage =
				(100.0 * count) / ((FunctionBitPatternsGTree) this.getTree()).getTotalNum();
		}
	}

	@Override
	public int compareTo(GTreeNode other) {
		if (other instanceof FunctionBitPatternsGTreeNode) {
			return -Integer.compare(count, ((FunctionBitPatternsGTreeNode) other).getCount());
		}
		return getName().compareToIgnoreCase(other.getName());
	}

	/**
	 * Get the count of sequences which pass through this node
	 * @return the count
	 */
	public int getCount() {
		return count;
	}

	/**
	 * Increment the count of sequences which pass through this node by amount
	 * @param amount amount to increment
	 */
	public void incrementCount(int amount) {
		count += amount;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (getChildren() == null || getChildren().isEmpty()) {
			return DISABLED_ICON;
		}
		return ENABLED_ICON;
	}

	@Override
	public String getToolTip() {
		StringBuilder sb = new StringBuilder();
		sb.append(count);
		sb.append(" (");
		sb.append(Double.toString(((Math.round(percentage * 10) * 1.0) / 10)));
		sb.append("%)");
		String tip = sb.toString();
		return tip;
	}

	@Override
	public boolean isLeaf() {
		return isLeaf;
	}

	/**
	 * Get the name of the instruction corresponding to this node
	 * @return instruction
	 */
	public String getInstruction() {
		return instruction;
	}

	/**
	 * Get the number of bytes in the instruction corresponding to this node
	 * @return number of bytes
	 */
	public Integer getNumBytes() {
		return numBytes;
	}

	/**
	 * Get the percentage of all instruction sequences which pass through this node
	 * 
	 * @return percentage
	 */
	public double getPercentage() {
		return percentage;
	}

	/**
	 * Filter out nodes in the tree by the percentage of instruction sequences which pass through them
	 * @param filter the percentage filter
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
		return;
	}
}
