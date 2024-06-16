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
import java.util.StringTokenizer;

import com.google.gson.JsonArray;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.relocs.SarifRelocationWriter;

public class RelocationTableSarifMgr extends SarifMgr {

	public static String KEY = "RELOCATIONS";
	public static String SUBKEY = "Relocation";

	RelocationTableSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws CancelledException {
		RelocationTable relocTable = program.getRelocationTable();

		try {
			Address addr = getLocation(result);
			int type = Integer.parseInt((String) result.get("kind"));
			long[] values = unpackLongs((String) result.get("value"));
			byte[] bytes = unpackBytes((String) result.get("bytes")); // optional
			String symbolName = (String) result.get("name"); // optional

			Status status = Status.UNKNOWN;
			if (bytes == null) {
				if (status != null && status.hasBytes()) {
					log.appendMsg("Relocation at " + addr + " missing required bytes - forced UNKNOWN status.");
					status = Status.UNKNOWN;
				}
			} else if (status == null) {
				status = type == 0 ? Status.APPLIED_OTHER : Status.APPLIED;
			}

			relocTable.add(addr, status, type, values, bytes, symbolName);
		} catch (AddressOverflowException e) {
			log.appendException(e);
		}
		return true;
	}

	private long[] unpackLongs(String attrValue) {
		if (attrValue == null) {
			return null;
		}
		StringTokenizer st = new StringTokenizer(attrValue, ",");
		long[] values = new long[st.countTokens()];
		int index = 0;
		while (st.hasMoreTokens()) {
			values[index++] = parseLong(st.nextToken());
		}
		return values;
	}

	private byte[] unpackBytes(String attrValue) {
		if (attrValue == null) {
			return null;
		}
		StringTokenizer st = new StringTokenizer(attrValue, ",");
		byte[] values = new byte[st.countTokens()];
		int index = 0;
		while (st.hasMoreTokens()) {
			values[index++] = (byte) parseLong(st.nextToken());
		}
		return values;
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	void write(JsonArray results, TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Writing RELOCATION TABLE ...");

		List<Relocation> request = new ArrayList<>();
		Iterator<Relocation> iter = program.getRelocationTable().getRelocations();
		while (iter.hasNext()) {
			monitor.checkCancelled();
			request.add(iter.next());
		}

		writeAsSARIF(request, results);
	}

	public static void writeAsSARIF(List<Relocation> request, JsonArray results) throws IOException {
		SarifRelocationWriter writer = new SarifRelocationWriter(request, null);
		new TaskLauncher(new SarifWriterTask(SUBKEY, writer, results), null);
	}

}
