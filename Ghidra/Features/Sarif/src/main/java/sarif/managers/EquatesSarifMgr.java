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
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.equates.SarifEquateWriter;

/**
 * SARIF manager for Equates.
 */
public class EquatesSarifMgr extends SarifMgr {

	public static String KEY = "EQUATES";
	public static String SUBKEY = "Equate";

	private EquateTable equateTable;

	EquatesSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
		this.equateTable = program.getEquateTable();
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	/**
	 * Process the entry point section of the SARIF file.
	 * 
	 * @param result  sarif reader
	 * @param monitor monitor that can be canceled
	 */
	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws CancelledException {
		processEquate(result, monitor);
		return true;
	}

	private void processEquate(Map<String, Object> result, TaskMonitor monitor) {
		String name = (String) result.get("name");
		long value = (long) (double) result.get("value");

		try {
			equateTable.createEquate(name, value);
		} catch (DuplicateNameException e) {
			Equate eq = equateTable.getEquate(name);
			long prevVal = eq.getValue();
			if (prevVal != value) {
				log.appendMsg("Cannot create equate [" + name + "] with value [" + value
						+ "]; previously defined with value [" + prevVal + "]");
			}
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	/**
	 * Write out the SARIF for the Equates.
	 * 
	 * @param results writer for SARIF
	 * @param set     address set that is either the entire program or a selection
	 * @param monitor monitor that can be canceled should be written
	 * @throws IOException
	 */
	void write(JsonArray results, AddressSetView set, TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Writing EQUATES ...");

		List<Equate> request = new ArrayList<>();
		Iterator<Equate> iter = equateTable.getEquates();
		while (iter.hasNext()) {
			request.add(iter.next());
		}

		writeAsSARIF(request, results);	
	}

	public static void writeAsSARIF(List<Equate> request, JsonArray results) throws IOException {
		SarifEquateWriter writer = new SarifEquateWriter(request, null);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

}
