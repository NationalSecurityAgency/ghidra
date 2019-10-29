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

import javax.swing.Icon;
import javax.swing.ImageIcon;

import docking.widgets.tree.GTreeNode;
import ghidra.app.util.ToolTipUtils;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class FunctionSymbolNode extends SymbolNode {
	static final DataFlavor LOCAL_DATA_FLAVOR =
		new SymbolTreeDataFlavor("Symbol Tree Data Flavor - Local Functions");
	static final DataFlavor GLOBAL_DATA_FLAVOR =
		new SymbolTreeDataFlavor("Symbol Tree Data Flavor - Global Functions");
	static final DataFlavor EXTERNAL_DATA_FLAVOR =
		new SymbolTreeDataFlavor("Symbol Tree Data Flavor - External Functions");

	public static final Icon FUNCTION_ICON = ResourceManager.loadImage("images/FunctionScope.gif");
	public static final Icon THUNK_ICON = ResourceManager.loadImage("images/ThunkFunction.gif");
	public static final Icon EXTERNAL_ICON =
		ResourceManager.loadImage("images/ExternalFunction.gif");
	public static final Icon DISABLED_FUNCTION_ICON =
		ResourceManager.getDisabledIcon((ImageIcon) FUNCTION_ICON);
	public static final Icon DISABLED_THUNK_ICON =
		ResourceManager.getDisabledIcon((ImageIcon) THUNK_ICON);
	public static final Icon DISABLED_EXTERNAL_ICON =
		ResourceManager.getDisabledIcon((ImageIcon) EXTERNAL_ICON);

	private static Comparator<GTreeNode> CHILD_COMPARATOR = new FunctionVariableComparator();

	private String tooltip;

	private boolean isExternal;

	FunctionSymbolNode(Program program, Symbol symbol) {
		super(program, symbol);
	}

	private boolean isThunk() {
		Function func = (Function) symbol.getObject();
		if (func == null) {
			return false;
		}
		return func.isThunk();
	}

	@Override
	public String getToolTip() {
		if (tooltip == null) {
			createTooltip();
		}
		return tooltip;
	}

	private void createTooltip() {
		Function func = (Function) symbol.getObject();
		if (func == null) {
			// unusual case
			tooltip = "No function for " + symbol.getName();
		}
		else {
			tooltip = ToolTipUtils.getToolTipText(func, true);
		}
	}

	@Override
	public Icon getIcon(boolean expanded) {
		boolean cut = isCut();
		if (symbol.isExternal()) {
			return cut ? DISABLED_EXTERNAL_ICON : EXTERNAL_ICON;
		}
		else if (isThunk()) {
			return cut ? DISABLED_THUNK_ICON : THUNK_ICON;
		}
		return cut ? DISABLED_FUNCTION_ICON : FUNCTION_ICON;
	}

	@Override
	public DataFlavor getNodeDataFlavor() {
		if (isExternal) {
			return EXTERNAL_DATA_FLAVOR;
		}
		return symbol.isGlobal() ? GLOBAL_DATA_FLAVOR : LOCAL_DATA_FLAVOR;
	}

	@Override
	public boolean canCut() {
		return true;
	}

	@Override
	public Comparator<GTreeNode> getChildrenComparator() {
		return CHILD_COMPARATOR;
	}

	@Override
	public GTreeNode findSymbolTreeNode(SymbolNode key, boolean loadChildren,
			TaskMonitor taskMonitor) {

		Symbol searchSymbol = key.getSymbol();
		if (symbol == searchSymbol) {
			return this;
		}

		if (!isChildType(searchSymbol.getSymbolType())) {
			// the symbol is not a child type of a function (like another function or a library)
			return null;
		}

		return super.findSymbolTreeNode(key, loadChildren, taskMonitor);
	}

	private boolean isChildType(SymbolType type) {
		//@formatter:off
		return type == SymbolType.PARAMETER || 
			   type == SymbolType.LOCAL_VAR ||
			   type == SymbolType.LABEL ||    // label function namespace 
			   type == SymbolType.NAMESPACE; // namespace in function namespace
		//@formatter:on
	}
//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class FunctionVariableComparator implements Comparator<GTreeNode> {
		@Override
		public int compare(GTreeNode o1, GTreeNode o2) {
			SymbolNode symbolNode1 = (SymbolNode) o1;
			SymbolNode symbolNode2 = (SymbolNode) o2;

			Symbol symbol1 = symbolNode1.getSymbol();
			Symbol symbol2 = symbolNode2.getSymbol();

			Object symbolObject1 = symbol1.getObject();
			Object symbolObject2 = symbol2.getObject();

			if ((symbolObject1 instanceof Variable) && (symbolObject2 instanceof Variable)) {
				Variable v1 = (Variable) symbolObject1;
				Variable v2 = (Variable) symbolObject2;
				return v1.compareTo(v2);
			}
			if (symbolObject1 instanceof Variable) {
				return -1;
			}
			if (symbolObject2 instanceof Variable) {
				return 1;
			}

			return o1.compareTo(o2);
		}
	}
}
