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
package ghidra.feature.vt.gui.provider.matchtable;

import docking.widgets.table.DisplayStringProvider;
import ghidra.program.model.symbol.Symbol;

public class DisplayableLabel implements DisplayStringProvider, Comparable<DisplayableLabel> {

	protected final Symbol symbol;

	public DisplayableLabel(Symbol symbol) {
		this.symbol = symbol;
	}

	public Symbol getSymbol() {
		return symbol;
	}

	@Override
	public String getDisplayString() {
		if (symbol == null) {
			return "<No Symbol>";
		}
		return symbol.getName();
	}

	@Override
	public String toString() {
		return getDisplayString();
	}

	@Override
	public int compareTo(DisplayableLabel otherDisplayableLabel) {
		if (otherDisplayableLabel == null) {
			return 1;
		}
		Symbol otherSymbol = otherDisplayableLabel.getSymbol();
		if (symbol == null) {
			return (otherSymbol == null) ? 0 : -1;
		}
		if (otherSymbol == null) {
			return 1;
		}
		return symbol.getName().compareToIgnoreCase(otherSymbol.getName());
	}

}
