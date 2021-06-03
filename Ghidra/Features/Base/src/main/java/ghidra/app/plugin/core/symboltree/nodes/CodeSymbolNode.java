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

import ghidra.app.util.ToolTipUtils;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Symbol;
import resources.ResourceManager;

public class CodeSymbolNode extends SymbolNode {
	static final DataFlavor LOCAL_DATA_FLAVOR =
		new SymbolTreeDataFlavor("Symbol Tree Data Flavor - Local Labels");
	static final DataFlavor GLOBAL_DATA_FLAVOR =
		new SymbolTreeDataFlavor("Symbol Tree Data Flavor - Global Labels");
	static final DataFlavor EXTERNAL_DATA_FLAVOR =
		new SymbolTreeDataFlavor("Symbol Tree Data Flavor - External Data");

	private static final Icon CODE_ICON = ResourceManager.loadImage("images/label.png");
	private static final Icon PINNED_ICON = ResourceManager.loadImage("images/pin.png");
	private static final Icon EXTERNAL_ICON = ResourceManager.loadImage("images/ExternalData.gif");
	private static final Icon DISABLED_CODE_ICON =
		ResourceManager.getDisabledIcon((ImageIcon) CODE_ICON);
	private static final Icon DISABLED_EXTERNAL_ICON =
		ResourceManager.getDisabledIcon((ImageIcon) EXTERNAL_ICON);

	private String tooltip;

	private boolean isExternal;

	public CodeSymbolNode(Program program, Symbol symbol) {
		super(program, symbol);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		if (isCut()) {
			return isExternal ? DISABLED_EXTERNAL_ICON : DISABLED_CODE_ICON;
		}
		if (isExternal) {
			return EXTERNAL_ICON;
		}
		return symbol.isPinned() ? PINNED_ICON : CODE_ICON;
	}

	@Override
	public String getToolTip() {
		if (tooltip == null) {
			createTooltip();
		}
		return tooltip;
	}

	private void createTooltip() {
		if (symbol.isExternal()) {
			isExternal = true;
			tooltip = "External Symbol - " + symbol.getName(true);
			Object object = symbol.getObject();
			// Object might be null, so make sure we have an external location before adjusting tool tip.
			if (object instanceof ExternalLocation) {
				tooltip = ToolTipUtils.getToolTipText((ExternalLocation) object, true);
			}
		}
		else if (symbol.isGlobal()) {
			tooltip = "Global Symbol - " + symbol.getName(true);
		}
		else {
			tooltip = "Local Symbol - " + symbol.getName(true);
		}
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
		return !symbol.isExternal();
	}

	@Override
	public boolean isLeaf() {
		return true;
	}
}
