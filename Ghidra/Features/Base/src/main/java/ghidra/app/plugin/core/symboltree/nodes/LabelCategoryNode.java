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
import java.util.Comparator;
import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class LabelCategoryNode extends SymbolCategoryNode {

	public static final Icon OPEN_FOLDER_LABELS_ICON =
		ResourceManager.loadImage("images/openFolderLabels.png");
	public static final Icon CLOSED_FOLDER_LABELS_ICON =
		ResourceManager.loadImage("images/closedFolderLabels.png");

	public LabelCategoryNode(Program program) {
		super(SymbolCategory.LABEL_CATEGORY, program);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_FOLDER_LABELS_ICON : CLOSED_FOLDER_LABELS_ICON;
	}

	@Override
	public String getToolTip() {
		return "Symbols for Global Labels";
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		for (DataFlavor flavor : dataFlavors) {
			if (flavor == CodeSymbolNode.LOCAL_DATA_FLAVOR) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected List<GTreeNode> getSymbols(SymbolType type, TaskMonitor monitor)
			throws CancelledException {
		return getSymbols(type, true, monitor);
	}

	@Override
	public boolean canPaste(List<GTreeNode> pastedNodes) {
		for (GTreeNode treeNode : pastedNodes) {
			if (!(treeNode instanceof LabelCategoryNode)) {
				return false;
			}
		}

		return true;
	}

	@Override
	public Comparator<GTreeNode> getChildrenComparator() {
		// this category node uses OrganizationNodes
		return OrganizationNode.COMPARATOR;
	}

	@Override
	public SymbolNode symbolAdded(Symbol symbol) {
		if (!isLoaded()) {
			return null;
		}

		// only include global symbols
		if (!symbol.isGlobal()) {
			return null;
		}

		if (!supportsSymbol(symbol)) {
			return null;
		}

		SymbolNode newNode = SymbolNode.createNode(symbol, program);
		doAddNode(this, newNode);
		return newNode;
	}
}
