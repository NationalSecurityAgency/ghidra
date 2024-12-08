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
import ghidra.docking.settings.Settings;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeInstance;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import sarif.SarifProgramOptions;
import sarif.export.SarifWriterTask;
import sarif.export.dd.SarifDataWriter;

public class DefinedDataSarifMgr extends SarifMgr {

	public static String KEY = "DEFINED_DATA";
	public static String SUBKEY = "Defined Data";

	DefinedDataSarifMgr(Program program, MessageLog log) {
		super(KEY, program, log);
	}

	////////////////////////////
	// SARIF READ CURRENT DTD //
	////////////////////////////

	@SuppressWarnings("unchecked")
	@Override
	public boolean read(Map<String, Object> result, SarifProgramOptions options, TaskMonitor monitor)
			throws CancelledException {

		Listing listing = program.getListing();
		DataTypeManager dataManager = program.getDataTypeManager();

		try {
			DtParser dtParser = new DtParser(dataManager);

			AddressSet set = getLocations(result, null);
			Address addr = set.getMinAddress();
			if (addr == null) {
				return false;
			}
			int size = (int) set.getMaxAddress().subtract(addr) + 1;

			String dataTypeName = (String) result.get("typeName");
			String typeLocation = (String) result.get("typeLocation");
			CategoryPath path = typeLocation != null ? new CategoryPath(typeLocation) : CategoryPath.ROOT;

			DataType dt = dtParser.parseDataType(dataTypeName, path, size);
			if (dt == null) {
				if (dataTypeName.contains(" ")) {
					dataTypeName = dataTypeName.substring(0, dataTypeName.indexOf(" "));
					dt = dtParser.parseDataType(dataTypeName, path, size);
				}
			}
			if (dt == null) {
				log.appendMsg("Defined root: unknown datatype: " + dataTypeName + " in category: " + path);
				return false;
			}

			try {
				if (options == null || options.isOverwriteDataConflicts()) {
					clearExistingData(addr, size, dt, listing);
				}

				Data data = listing.createData(addr, dt, size);
				processSettings(result, data);
				Map<String, Object> comments = (Map<String, Object>) result.get("nested");
				processComment(comments, data);

			} catch (CodeUnitInsertionException e) {
				Data d = listing.getDefinedDataAt(addr);
				if (d == null || !d.getDataType().isEquivalent(dt)) {
					log.appendMsg(e.getMessage());
				}
			} catch (Exception e) {
				log.appendException(e);
			}
		} catch (AddressOverflowException e1) {
			log.appendException(e1);
		} 
		return true;
	}

	@SuppressWarnings("unchecked")
	private void processSettings(Map<String, Object> res, Data data) {
		List<Map<String, Object>> settingsMap = (List<Map<String, Object>>) res.get("settings");
		if (settingsMap == null) {
			return;
		}
		for (Map<String, Object> map : settingsMap) {
			Settings settings = data.getDefaultSettings();
			if (map != null) {
				String name = (String) map.get("name");
				String kind = (String) map.get("kind");
				String value = (String) map.get("value");
				Object existing = settings.getValue(name);
				if (existing == null || !existing.toString().equals(value)) {
					settings.setValue(name, kind.equals("long") ? Long.parseLong(value) : value);
				}
			}
		}
	}

	@SuppressWarnings("unchecked")
	private void processComment(Map<String, Object> c, Data data) {
		if (c == null || c.isEmpty()) {
			return;
		}
		List<Map<String, Object>> localComments = (List<Map<String, Object>>) c.get("comment");
		if (localComments != null) {
			for (Map<String, Object> lmap : localComments) {
				String comment = (String) lmap.get("comment");
				int type = (int) (double) lmap.get("commentType");
				String existing = data.getComment(type);
				if (existing == null || !existing.equals(comment)) {
					data.setComment(type, comment);
				}
			}
		}
		List<Map<String, Object>> localSettings = (List<Map<String, Object>>) c.get("setting");
		if (localSettings != null) {
			for (Map<String, Object> lmap : localSettings) {
				String name = (String) lmap.get("name");
				String kind = (String) lmap.get("kind");
				String value = (String) lmap.get("value");
				Object existing = data.getValue(name);
				if (existing == null || !existing.toString().equals(value)) {
					data.setValue(name, kind.equals("long") ? Long.parseLong(value) : value);
				}
			}
		}
		Map<String, Map<String, Object>> embedded = (Map<String, Map<String, Object>>) c.get("embedded");
		if (embedded != null) {
			for (String index : embedded.keySet()) {
				Data component = data.getComponent(Integer.parseInt(index));
				Map<String, Object> c2 = embedded.get(index);
				processComment(c2, component);
			}
		}
	}

	private void clearExistingData(Address addr, int size, DataType dt, Listing listing) {
		DumbMemBufferImpl buf = new DumbMemBufferImpl(program.getMemory(), addr);
		DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(dt, buf, size, false);
		if (dti != null) {
			boolean doClear = false;
			Address maxAddr = addr.add(dti.getLength() - 1);
			CodeUnitIterator codeUnits = listing.getCodeUnitIterator(CodeUnit.DEFINED_DATA_PROPERTY, new AddressSet(addr, maxAddr), true);
			while (codeUnits.hasNext()) {
				CodeUnit cu = codeUnits.next();
				if (cu instanceof Data) {
					if (((Data) cu).isDefined()) {
						doClear = true;
					}
				} else {
					return; // don't clear instructions
				}
			}
			if (doClear) {
				listing.clearCodeUnits(addr, maxAddr, false);
			}
		}
	}

	/////////////////////////////
	// SARIF WRITE CURRENT DTD //
	/////////////////////////////

	void write(JsonArray results, AddressSetView addrset, TaskMonitor monitor) throws IOException, CancelledException {
		monitor.setMessage("Writing DATA ...");

		List<Data> request = new ArrayList<>();
		Listing listing = program.getListing();
		DataIterator iter = listing.getDefinedData(addrset, true);
		while (iter.hasNext()) {
			request.add(iter.next());
		}

		writeAsSARIF(program, request, results);
	}

	public static void writeAsSARIF(Program program, List<Data> request, JsonArray results) throws IOException {
		SarifDataWriter writer = new SarifDataWriter(request, null);
		new TaskLauncher(new SarifWriterTask("DefinedData", writer, results), null);
	}

}
