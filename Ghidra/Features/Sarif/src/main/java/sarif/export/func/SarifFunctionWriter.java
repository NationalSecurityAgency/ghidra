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
package sarif.export.func;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonArray;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.export.symbols.ExtSymbol;
import sarif.managers.FunctionsSarifMgr;
import sarif.managers.SymbolTableSarifMgr;

public class SarifFunctionWriter extends AbstractExtWriter {
	
	private List<Function> requestedFunctions = new ArrayList<>();

	public SarifFunctionWriter(FunctionManager mgr, List<Function> requestedFunctions, Writer baseWriter) throws IOException {
		super(baseWriter);
		this.requestedFunctions = requestedFunctions;
	}

	public void requestFunction(Function next) {
		requestedFunctions.add(next);
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genFunctions(monitor);
		root.add("functions", objects);
	}

	private void genFunctions(TaskMonitor monitor) throws CancelledException, IOException{
		monitor.initialize(requestedFunctions.size());
		for (Function f : requestedFunctions) {
			addSymbol(f.getSymbol());
			ExtFunction isf = new ExtFunction(f, monitor);
			SarifObject sarif = new SarifObject("Function", FunctionsSarifMgr.KEY, getTree(isf), f.getBody());
			objects.add(getTree(sarif));
			monitor.increment();
		}
	}
	
	private void addSymbol(Symbol s) {
		Namespace pspace = s.getParentNamespace();
		if (pspace == null) {
			return;
		}
		if (!pspace.isGlobal()) {
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
