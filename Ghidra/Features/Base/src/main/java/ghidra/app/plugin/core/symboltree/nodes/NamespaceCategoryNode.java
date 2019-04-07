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

import javax.swing.Icon;

import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import resources.ResourceManager;

public class NamespaceCategoryNode extends SymbolCategoryNode {

	public static final Icon OPEN_FOLDER_NAMESPACES_ICON =
		ResourceManager.loadImage("images/openFolderNamespaces.png");
	public static final Icon CLOSED_FOLDER_NAMESPACES_ICON =
		ResourceManager.loadImage("images/closedFolderNamespaces.png");

	NamespaceCategoryNode(Program program) {
		super(SymbolCategory.NAMESPACE_CATEGORY, program);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_FOLDER_NAMESPACES_ICON : CLOSED_FOLDER_NAMESPACES_ICON;
	}

	@Override
	protected boolean supportsSymbol(Symbol symbol) {
		if (super.supportsSymbol(symbol)) {
			return true;
		}

		// must be in a non-global namespace
		Namespace parentNamespace = symbol.getParentNamespace();
		return parentNamespace != null && parentNamespace != globalNamespace;
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		for (DataFlavor flavor : dataFlavors) {
			if (isSupportedLocalFlavor(flavor)) {
				return true;
			}
		}
		return false;
	}

	public boolean isSupportedLocalFlavor(DataFlavor flavor) {
		if (!isLocalDataFlavor(flavor)) {
			return false;
		}

		// we don't know how to add a class to the top-level category node
		return flavor != ClassSymbolNode.LOCAL_DATA_FLAVOR;
	}
}
