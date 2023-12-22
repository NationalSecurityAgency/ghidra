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
package sarif.export.symbols;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;

import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.SymbolTableSarifMgr;

public class SarifSymbolWriter extends AbstractExtWriter {
	
	private List<Symbol> symbols = new ArrayList<>();

	public SarifSymbolWriter(List<Symbol> request, Writer baseWriter) throws IOException {
		super(baseWriter);
		this.symbols = request;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genSymbols(monitor);
		root.add("definedData", objects);
	}

	private void genSymbols(TaskMonitor monitor) throws CancelledException, IOException{
		monitor.initialize(symbols.size());
		for (Symbol s : symbols) {
			SymbolType symbolType = s.getSymbolType();
			if (s.getSource() == SourceType.DEFAULT) {
				continue;
			}

			if (symbolType != SymbolType.LABEL && symbolType != SymbolType.FUNCTION) {
				continue;
			}
			
			addSymbol(s);
			monitor.increment();
		}
	}
	
	private void addSymbol(Symbol s) {
		if (!s.getParentNamespace().isGlobal()) {
			Symbol p = s.getParentSymbol();
			addSymbol(p);
		}
		ExtSymbol lib = new ExtSymbol(s);
		SarifObject sarif = new SarifObject("Symbol", SymbolTableSarifMgr.KEY, getTree(lib), s.getAddress(), s.getAddress());
		objects.add(getTree(sarif));
	}
	
	public JsonArray getResults() {
		return objects;
	}

}
