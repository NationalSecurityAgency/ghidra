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
package sarif.managers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.symbols.SarifSymbolWriter;

/**
 * SARIF manager for the Symbol Table.
 *
 */
public class SymbolTableSarifMgr extends SarifMgr {

	public static String KEY = "SYMBOLS";
	public static String SUBKEY = "Symbols";

	private SymbolTable symbolTable;
	private boolean overwritePrimary;
	private boolean preFunction;

	SymbolTableSarifMgr(Program program, MessageLog log, boolean preFunction) {
		super(KEY, program, log);
		this.preFunction = preFunction;
		symbolTable = program.getSymbolTable();
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	/**
	 * Process the symbol table section of the SARIF file.
	 */
	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws CancelledException {
		this.overwritePrimary = options == null || options.isOverwriteSymbolConflicts();
		processSymbol(result, preFunction);
		return true;
	}

	private void processSymbol(Map<String, Object> result, boolean firstPass) {
		try {
			String kind = (String) result.get("kind");
			boolean isLocal = (kind != null) && kind.equalsIgnoreCase("local");
			String type = (String) result.get("type");

			boolean isPrimary = (boolean) result.get("primary");
			boolean isPinned = (boolean) result.get("pinned");
			String sourceTypeString = (String) result.get("sourceType");
			SourceType sourceType = getSourceType(sourceTypeString);

			String name = (String) result.get("name");
			boolean processFirstPass = true;
			if (isLocal && type == null) {
				processFirstPass = false;
			}
			if (sourceType.equals(SourceType.DEFAULT)) {
				processFirstPass = false;
			}

			if (firstPass && !processFirstPass) {
				return;
			}
			if (!firstPass && processFirstPass) {
				return;
			}

			Address addr = getLocation(result);
			String namespace = (String) result.get("location");
			Boolean isClass = (Boolean) result.get("namespaceIsClass");
			Namespace scope = program.getGlobalNamespace(); // default to global scope
			scope = isLocal ? walkNamespace(scope, namespace, addr, sourceType, isClass) : scope;
			if (scope == null) {
				return;
			}

			if (type != null) {
				if (type.equals("namespace")) {
					if (symbolTable.getNamespace(name, scope) == null) {
						symbolTable.createNameSpace(scope, name, sourceType);
					}
					return;
				}
				if (type.equals("class")) {
					if (symbolTable.getClassSymbol(name, scope) == null) {
						symbolTable.createClass(scope, name, sourceType);
					}
					return;
				}
				if (type.equals("library")) {
					if (symbolTable.getLibrarySymbol(name) == null) {
						symbolTable.createExternalLibrary(name, sourceType);
					}
					return;
				}
			}

			if (symbolTable.getSymbol(name, addr, scope) == null) {
				Symbol s = SymbolUtilities.createPreferredLabelOrFunctionSymbol(program, addr, scope, name, sourceType);
				if (s != null && isPrimary && overwritePrimary) {
					s.setPrimary();
				}
				if (isPinned) {
					s.setPinned(true);
				}
			}
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	/**
	 * Write out the SARIF for the symbol table.
	 * 
	 * @param results writer for SARIF
	 * @param monitor monitor that can be canceled should be written
	 * @throws IOException
	 */
	void write(JsonArray results, AddressSetView set, TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Writing SYMBOL TABLE ...");

		SymbolIterator iter = symbolTable.getSymbolIterator();
		List<Symbol> request = new ArrayList<>();
		while (iter.hasNext()) {
			request.add(iter.next());
		}

		writeAsSARIF(program, request, results);
	}

	public static void writeAsSARIF(Program program, List<Symbol> request, JsonArray results) throws IOException {
		SarifSymbolWriter writer = new SarifSymbolWriter(request, null);
		new TaskLauncher(new SarifWriterTask("Symbols", writer, results), null);
	}

}
