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

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import resources.ResourceManager;

public class ParameterSymbolNode extends SymbolNode {

	public static final Icon PARAMETER_ICON = ResourceManager.loadImage("images/Parameter.gif");

	ParameterSymbolNode(Program program, Symbol symbol) {
		super(program, symbol);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return PARAMETER_ICON;
	}

	@Override
	public void setNodeCut(boolean isCut) {
		throw new UnsupportedOperationException("Cannot cut a parameter node");
	}

	@Override
	public boolean isLeaf() {
		return true;
	}
}
