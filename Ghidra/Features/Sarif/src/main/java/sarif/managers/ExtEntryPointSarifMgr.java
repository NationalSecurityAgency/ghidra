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
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.ep.SarifEntryPointWriter;

/**
 * SARIF manager for External Entry Points.
 */
public class ExtEntryPointSarifMgr extends SarifMgr {

	public static String KEY = "ENTRY_POINTS";
	public static String SUBKEY = "Entry Point";

	private SymbolTable symbolTable;

	ExtEntryPointSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
		symbolTable = program.getSymbolTable();
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	/**
	 * Process the entry point section of the SARIF file.
	 * 
	 * @param result  sarif
	 * @param monitor monitor that can be canceled
	 */
	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws AddressFormatException, CancelledException {
		try {
			Address addr = getLocation(result);
			symbolTable.addExternalEntryPoint(addr);
			return true;
		} catch (Exception e) {
			log.appendException(e);
		}
		return false;
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	/**
	 * Write out the SARIF for the external entry points.
	 * 
	 * @param results writer for SARIF
	 * @param set     address set that is either the entire program or a selection
	 * @param monitor monitor that can be canceled should be written
	 * @throws IOException
	 */
	void write(JsonArray results, AddressSetView set, TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Writing ENTRY POINTS ...");

		List<Address> request = new ArrayList<>();
		AddressIterator iter = symbolTable.getExternalEntryPointIterator();
		while (iter.hasNext()) {
			request.add(iter.next());
		}

		writeAsSARIF(request, results);
	}

	public static void writeAsSARIF(List<Address> request, JsonArray results) throws IOException {
		SarifEntryPointWriter writer = new SarifEntryPointWriter(request, null);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

}
