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
package sarif.export.extlib;

import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.google.gson.JsonArray;

import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import sarif.export.AbstractExtWriter;
import sarif.export.SarifObject;
import sarif.managers.ExternalLibSarifMgr;

public class SarifClassesNamespaceWriter extends AbstractExtWriter {

	private List<GhidraClass> classes = new ArrayList<>();
	private ExternalManager externalManager;
	private SymbolTable symbolTable;

	public SarifClassesNamespaceWriter(ExternalManager externalManager, SymbolTable symbolTable, List<GhidraClass> request, Writer baseWriter)
			throws IOException {
		super(baseWriter);
		this.externalManager = externalManager;
		this.symbolTable = symbolTable;
		this.classes = request;
	}

	@Override
	protected void genRoot(TaskMonitor monitor) throws CancelledException, IOException {
		genClasses(monitor);
		root.add("definedData", objects);
	}

	private void genClasses(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.initialize(classes.size());
		Iterator<GhidraClass> classNamespaces = symbolTable.getClassNamespaces();
		while (classNamespaces.hasNext()) {
			GhidraClass next = classNamespaces.next();
			walkSymbols(next);
			monitor.increment();
		}
	}

	private void walkSymbols(GhidraClass cls) {
		String clsName = cls.getName(true);
		String path = externalManager.getExternalLibraryPath(clsName);
		if (path == null) {
			path = "";
		}
		ExtLibrary lib = new ExtLibrary(clsName, path, SourceType.DEFAULT);
		SarifObject sarif = new SarifObject(ExternalLibSarifMgr.SUBKEY0, ExternalLibSarifMgr.KEY, getTree(lib), null);
		objects.add(getTree(sarif));
		
		SymbolIterator symbols = symbolTable.getSymbols(cls);
		while (symbols.hasNext()) {
			Symbol sym = symbols.next();
			if (cls.isExternal()) {
				ExternalLocation loc = externalManager.getExternalLocation(sym);
				ExtLibraryLocation obj = new ExtLibraryLocation(loc);
				SarifObject sarif2 = new SarifObject(ExternalLibSarifMgr.SUBKEY1, ExternalLibSarifMgr.KEY, getTree(obj),
						loc.getAddress(), loc.getAddress());
				objects.add(getTree(sarif2));
			}
		}
	}

	public JsonArray getResults() {
		return objects;
	}

}
