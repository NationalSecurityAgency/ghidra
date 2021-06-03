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

public class ClassSymbolNode extends SymbolNode {
	static final DataFlavor LOCAL_DATA_FLAVOR =
		new SymbolTreeDataFlavor("Symbol Tree Data Flavor - Local Classes");
	static final DataFlavor GLOBAL_DATA_FLAVOR =
		new SymbolTreeDataFlavor("Symbol Tree Data Flavor - Global Classes");

	private static Icon CLASS_ICON = ResourceManager.loadImage("images/class.png");
	private static Icon DISABLED_CLASS_ICONDISABLED_CLASS_ICON =
		ResourceManager.getDisabledIcon((ImageIcon) CLASS_ICON);

	ClassSymbolNode(Program program, Symbol symbol) {
		super(program, symbol);

	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (isCut()) {
			return DISABLED_CLASS_ICONDISABLED_CLASS_ICON;
		}
		return CLASS_ICON;
	}

	@Override
	public DataFlavor getNodeDataFlavor() {
		return symbol.isGlobal() ? GLOBAL_DATA_FLAVOR : LOCAL_DATA_FLAVOR;
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		for (DataFlavor flavor : dataFlavors) {
			if (symbol.isExternal()) {
				if (isExternal(flavor)) {
					return true;
				}
			}
			if (isLabelOrFunction(flavor)) {
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

	private boolean isExternal(DataFlavor dataFlavor) {
		return dataFlavor == CodeSymbolNode.EXTERNAL_DATA_FLAVOR ||
			dataFlavor == FunctionSymbolNode.EXTERNAL_DATA_FLAVOR;
	}

	private boolean isLabelOrFunction(DataFlavor dataFlavor) {
		return dataFlavor == CodeSymbolNode.GLOBAL_DATA_FLAVOR ||
			dataFlavor == CodeSymbolNode.LOCAL_DATA_FLAVOR ||
			dataFlavor == FunctionSymbolNode.GLOBAL_DATA_FLAVOR ||
			dataFlavor == FunctionSymbolNode.LOCAL_DATA_FLAVOR;

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
