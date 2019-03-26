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
// Shows how to find data types by name in data type managers other than the current program's, 
// which is how the <tt>GhidraScript.getDataTypes(String)</tt> works.
//@category Examples

import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;

import java.util.Iterator;

public class FindDataTypeScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		DataTypeManager manager = getDataTypeManagerByName("generic_C_lib");
		if (manager == null) {
			println("Archive must not be open in the Data Type Manager");
			return;
		}

		DataType specificDataType = manager.getDataType("/complex.h/defines/define__COMPLEX_H");
		println("Data type: " + specificDataType);

		//
		// without the category path
		//
		println("Now searching for any matching type in generic_C_lib:");
		Iterator<DataType> allDataTypes = manager.getAllDataTypes();
		while (allDataTypes.hasNext()) {
			DataType dataType = allDataTypes.next();
			String dataTypeName = dataType.getName();
			if (dataTypeName.indexOf("COMPLEX") != -1) {
				println("\tFound match: " + dataType);
			}
		}
		println("Done searching");

		//
		// In the built-in DTM		
		//
		manager = getDataTypeManagerByName("BuiltInTypes");
		println("Now searching for any matching type in BuiltInTypes:");
		allDataTypes = manager.getAllDataTypes();
		while (allDataTypes.hasNext()) {
			DataType dataType = allDataTypes.next();
			String dataTypeName = dataType.getName();
			if (dataTypeName.indexOf("sdword") != -1) {
				println("\tFound match: " + dataType);
			}
		}
		println("Done searching");
	}

	private DataTypeManager getDataTypeManagerByName(String name) {
		PluginTool tool = state.getTool();
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		DataTypeManager[] dataTypeManagers = service.getDataTypeManagers();
		for (DataTypeManager manager : dataTypeManagers) {
			String managerName = manager.getName();
			if (name.equals(managerName)) {
				return manager;
			}
		}
		return null;
	}
}
