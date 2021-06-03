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
import javax.swing.ImageIcon;

import ghidra.app.util.SelectionTransferData;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import resources.ResourceManager;

public class NamespaceSymbolNode extends SymbolNode {
	static final DataFlavor LOCAL_DATA_FLAVOR =
		new SymbolTreeDataFlavor("Symbol Tree Data Flavor - Local Namespaces");
	static final DataFlavor GLOBAL_DATA_FLAVOR =
		new SymbolTreeDataFlavor("Symbol Tree Data Flavor - Global Namespaces");

	public static final Icon NAMESPACE_ICON = ResourceManager.loadImage("images/Namespace.gif");
	public static final Icon DISABLED_NAMESPACE_ICON =
		ResourceManager.getDisabledIcon((ImageIcon) NAMESPACE_ICON);

	NamespaceSymbolNode(Program program, Symbol symbol) {
		super(program, symbol);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (isCut()) {
			return DISABLED_NAMESPACE_ICON;
		}
		return NAMESPACE_ICON;
	}

	@Override
	public DataFlavor getNodeDataFlavor() {
		return symbol.isGlobal() ? GLOBAL_DATA_FLAVOR : LOCAL_DATA_FLAVOR;
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		for (DataFlavor flavor : dataFlavors) {
			if (flavor instanceof SymbolTreeDataFlavor) {
				return true;
			}

			if (isProgramSelection(flavor)) {
				return true;
			}
		}
		return false;
	}

	private boolean isProgramSelection(DataFlavor flavor) {
		Class<?> clazz = flavor.getRepresentationClass();
		return SelectionTransferData.class.equals(clazz);
	}

	@Override
	public Namespace getNamespace() {
		return (Namespace) symbol.getObject();
	}

	@Override
	public boolean canCut() {
		return true;
	}
}
