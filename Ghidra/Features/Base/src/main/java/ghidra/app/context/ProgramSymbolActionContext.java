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
package ghidra.app.context;

import java.awt.Component;
import java.util.*;

import docking.ComponentProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

public class ProgramSymbolActionContext extends ProgramActionContext {

	private List<Symbol> symbols = new ArrayList<Symbol>();

	public ProgramSymbolActionContext(ComponentProvider provider, Program program,
			List<Symbol> symbols, Component sourceComponent) {
		super(provider, program, sourceComponent);
		this.symbols = symbols == null ? Collections.emptyList() : symbols;
	}

	public int getSymbolCount() {
		return symbols.size();
	}

	public Symbol getFirstSymbol() {
		if (symbols.isEmpty()) {
			return null;
		}
		return symbols.get(0);
	}

	public Iterable<Symbol> getSymbols() {
		return symbols;
	}
}
