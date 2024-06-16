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
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.extlib.SarifClassesNamespaceWriter;
import sarif.export.extlib.SarifExternalLibraryWriter;

/**
 * SARIF for external library table for resolved external references.
 */
public class ExternalLibSarifMgr extends SarifMgr {

	public static String KEY = "EXT_LIBRARY";
	public static String SUBKEY0 = "External.Library";
	public static String SUBKEY1 = "External.Location";

	private ExternalManager extManager;
	private boolean libraries = true;

	ExternalLibSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
		extManager = program.getExternalManager();
		externalMap = new HashMap<>();
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	@Override
	protected void readResults(List<Map<String, Object>> list, SarifProgramOptions options, TaskMonitor monitor)
			throws AddressFormatException, CancelledException {
		if (list != null) {
			monitor.setMessage("Processing " + key + "...");
			monitor.setMaximum(list.size() * 2);

			for (Map<String, Object> result : list) {
				monitor.checkCancelled();
				read(result, options, monitor);
				monitor.increment();
			}
			libraries = false;
			for (Map<String, Object> result : list) {
				monitor.checkCancelled();
				read(result, options, monitor);
				monitor.increment();
			}

		} else {
			monitor.setMessage("Skipping over " + key + " ...");
		}
	}

	/**
	 * Process the entry point section of the SARIF file.
	 * 
	 * @param result  sarif reader
	 * @param monitor monitor that can be canceled
	 */
	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws CancelledException {
		try {
			String symbol = (String) result.get("symbol");
			if (libraries && symbol == null) {
				processExternalLib(result);
				return true;
			}
			if (!libraries && symbol != null) {
				processExternalLocation(result);
				return true;
			}
			return false;
		} catch (Exception e) {
			log.appendException(e);
		}
		return false;
	}

	private void processExternalLib(Map<String, Object> result) throws InvalidInputException, DuplicateNameException {

		String progName = (String) result.get("name");
		// check to make sure that we do not clear any
		// external refs that have already been resolved
		Library library = extManager.getExternalLibrary(progName);
		if (library != null) {
			return; // already has a value--don't override it
		}

		// NB: Can't use "DEFAULT" here or result.get("sourceType") which may be
		// "DEFAULT"
		String source = (String) result.get("sourceType");
		SourceType sourceType = getSourceType(source);
		if (sourceType.equals(SourceType.DEFAULT)) {
			sourceType = SourceType.IMPORTED;
		}
		library = extManager.addExternalLibraryName(progName, sourceType);
	}

	private void processExternalLocation(Map<String, Object> result) throws IOException {

		try {
			String name = (String) result.get("name");
			String location = (String) result.get("location");
			Address address = getLocation(result);
			String extern = (String) result.get("externalAddress");
			String source = (String) result.get("source");
			SourceType sourceType = getSourceType(source);
			if (sourceType.equals(SourceType.DEFAULT)) {
				sourceType = SourceType.IMPORTED;
			}
			boolean isClass = (boolean) result.get("isClass");
			Namespace p = walkNamespace(program.getGlobalNamespace(), location + "::", address, sourceType, isClass);
			String name0 = (String) result.get("originalImportedName");

			ExternalLocation loc = addExternal(result, name, address, sourceType, p, name0);
			externalMap.put(extern, loc);
		} catch (InvalidInputException | AddressOverflowException e) {
			log.appendException(e);
		}
	}

	private ExternalLocation addExternal(Map<String, Object> result, String name, Address address, SourceType sourceType,
			Namespace p, String name0) throws InvalidInputException {
		Library lib = getLibrary(p);
		ExternalLocation loc;
		if ((boolean) result.get("isFunction")) {
			if (name0 != null) {
				loc = extManager.addExtFunction(lib == null ? p : lib, name0, address, sourceType, false);
				loc.setName(p, name, sourceType);
			} else {
				loc = extManager.addExtFunction(p, name, address, sourceType, true);
			}
		} else {
			if (name0 != null) {
				loc = extManager.addExtLocation(lib == null ? p : lib, name0, address, sourceType, false);
				loc.setName(p, name, sourceType);
			} else {
				loc = extManager.addExtLocation(p, name, address, sourceType, true);
			}
		}
		return loc;
	}

	private Library getLibrary(Namespace p) {
		if (p instanceof Library lib) {
			return lib;
		}
		Namespace parent = p.getParentNamespace();
		return parent == null ? null : getLibrary(parent);
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	/**
	 * Write out the SARIF for the external library table.
	 * 
	 * @param results writer for SARIF
	 * @param monitor monitor that can be canceled should be written
	 * @throws IOException
	 */
	void write(JsonArray results, TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Writing EXTERNAL LIBRARIES ...");

		String[] externalNames = extManager.getExternalLibraryNames();
		List<String> request0 = new ArrayList<>();
		for (String name : externalNames) {
			request0.add(name);
		}

		writeExtAsSARIF(program, request0, results);
		
		Iterator<GhidraClass> classNamespaces = program.getSymbolTable().getClassNamespaces();
		List<GhidraClass> request1 = new ArrayList<>();
		while (classNamespaces.hasNext()) {
			request1.add(classNamespaces.next());
		}

		writeNamespaceAsSARIF(program, request1, results);

	}

	public static void writeExtAsSARIF(Program program, List<String> request, JsonArray results) throws IOException {
		SarifExternalLibraryWriter writer = new SarifExternalLibraryWriter(program.getExternalManager(), request, null);
		new TaskLauncher(new SarifWriterTask("Libraries", writer, results), null);
	}

	public static void writeNamespaceAsSARIF(Program program, List<GhidraClass> request, JsonArray results) throws IOException {
		SarifClassesNamespaceWriter writer = new SarifClassesNamespaceWriter(program.getExternalManager(), program.getSymbolTable(), request, null);
		new TaskLauncher(new SarifWriterTask("Libraries", writer, results), null);
	}

}
