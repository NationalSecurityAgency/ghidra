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
package ghidra.app.plugin.core.symboltree.nodes;

import java.awt.datatransfer.DataFlavor;
import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

/**
 * Node to represent nodes that are not shown. After showing a handful of symbol nodes
 * with the same name, this node will be used in place of the rest of the nodes and
 * will display "xx more..." where xx is the number of nodes that are not being shown. 
 * 
 */
public class MoreNode extends SymbolTreeNode {
	private static Icon ICON = Icons.MAKE_SELECTION_ICON;
	private int count;
	private String name;

	MoreNode(String name, int count) {
		this.name = name;
		this.count = count;
	}

	@Override
	public String getName() {
		return count + " more...";
	}

	@Override
	public boolean canCut() {
		return false;
	}

	@Override
	public boolean canPaste(List<GTreeNode> pastedNodes) {
		return false;
	}

	@Override
	public void setNodeCut(boolean isCut) {
		throw new UnsupportedOperationException("Cannot cut an organization node");
	}

	@Override
	public boolean isCut() {
		return false;
	}

	@Override
	public DataFlavor getNodeDataFlavor() {
		return null;
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		return false;
	}

	@Override
	public Namespace getNamespace() {
		return null;
	}

	@Override
	public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {
		// not used, children generated in constructor
		return null;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return ICON;
	}

	@Override
	public String getToolTip() {
		return "There are " + count + " nodes named \"" +
			name + "\" not being shown";
	}

	@Override
	public boolean isLeaf() {
		return true;
	}

	void incrementCount() {
		count++;
	}

	void decrementCount() {
		count = Math.max(0, --count);
	}

	boolean isEmpty() {
		return count == 0;
	}
}
