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

import javax.swing.Icon;

import ghidra.app.plugin.core.symboltree.SymbolCategory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import resources.ResourceManager;

public class ImportsCategoryNode extends SymbolCategoryNode {

	private static Icon CLOSED_FOLDER_EXTERNALS_ICON =
		ResourceManager.loadImage("images/closedFolderExternals.png");
	private static Icon OPEN_FOLDER_EXTERNALS_ICON =
		ResourceManager.loadImage("images/openFolderExternals.png");

	public ImportsCategoryNode(Program program) {
		super(SymbolCategory.IMPORTS_CATEGORY, program);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_FOLDER_EXTERNALS_ICON : CLOSED_FOLDER_EXTERNALS_ICON;
	}

	@Override
	public String getToolTip() {
		return "Symbols for External libraries";
	}

	@Override
	protected boolean supportsSymbol(Symbol symbol) {
		return symbol.isExternal();
	}
}
