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

import docking.widgets.tree.GTreeNode;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import resources.ResourceManager;

public class LibrarySymbolNode extends SymbolNode {

	private static final String ORDINAL_PREFIX = "Ordinal_";

	private static Icon LIBRARY_ICON = ResourceManager.loadImage("images/package.png");

	private static Comparator<GTreeNode> CHILD_COMPARATOR = (o1, o2) -> {
		SymbolNode symbolNode1 = (SymbolNode) o1;
		SymbolNode symbolNode2 = (SymbolNode) o2;

		Symbol s1 = symbolNode1.getSymbol();
		Symbol s2 = symbolNode2.getSymbol();

		Integer result = tryToCompareExternalLocationsByOrdinal(s1, s2);
		if (result != null) {
			return result;
		}

		return o1.compareTo(o2);
	};

	private static Integer tryToCompareExternalLocationsByOrdinal(Symbol s1, Symbol s2) {
		Object so1 = s1.getObject();
		if (!(so1 instanceof ExternalLocation)) {
			return null;
		}

		Object so2 = s2.getObject();
		if (!(so2 instanceof ExternalLocation)) {
			return null;
		}

		String n1 = s1.getName();
		String n2 = s2.getName();
		if (n1.startsWith(ORDINAL_PREFIX) && n2.startsWith(ORDINAL_PREFIX)) {
			try {
				int ordinal1 = Integer.parseInt(n1.substring(ORDINAL_PREFIX.length()));
				int ordinal2 = Integer.parseInt(n2.substring(ORDINAL_PREFIX.length()));
				return ordinal1 - ordinal2;
			}
			catch (NumberFormatException nfe) {
				// just perform default operation below
			}
		}

		return null;
	}

	private String tooltip;

	LibrarySymbolNode(Program program, Symbol symbol) {
		super(program, symbol);

		String name = symbol.getName();
		String externalLibraryPath = program.getExternalManager().getExternalLibraryPath(name);
		tooltip = "External Library Symbol - " + name;
		if (externalLibraryPath != null) {
			tooltip = tooltip + " - " + externalLibraryPath;
		}
	}

	@Override
	public Comparator<GTreeNode> getChildrenComparator() {
		return CHILD_COMPARATOR;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return LIBRARY_ICON;
	}

	@Override
	public String getToolTip() {
		return tooltip;
	}

	@Override
	public void setNodeCut(boolean isCut) {
		throw new UnsupportedOperationException("Cannot cut a library node");
	}

	@Override
	public boolean supportsDataFlavors(DataFlavor[] dataFlavors) {
		for (DataFlavor flavor : dataFlavors) {
			if (flavor instanceof SymbolTreeDataFlavor) {
				return true;
			}
		}
		return false;
	}

	@Override
	public Namespace getNamespace() {
		return (Library) symbol.getObject();
	}
}
