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
// Text-dump all data types from the user-specified DataTypeManager to the user-specified file.
//
//@category Data Types
import java.io.File;
import java.io.FileWriter;
import java.util.Iterator;

import docking.widgets.OptionDialog;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.ToolTipUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

public class DeveloperDumpAllTypesScript extends GhidraScript {

	@Override
	protected void run() throws Exception, CancelledException {

		DataTypeManager manager = userChooseDataTypeManager();
		if (manager == null) {
			return;
		}

		File dumpFile = askFile("Choose an output file", "OK");
		if (dumpFile == null) {
			Msg.info(this, "Canceled execution due to no output file");
			return;
		}
		if (dumpFile.exists()) {
			if (!askYesNo("Confirm Overwrite", "Overwrite file: " + dumpFile.getName())) {
				Msg.info(this, "Operation canceled");
				return;
			}
		}
		FileWriter fileWriter = new FileWriter(dumpFile);

		String message = "Outputting DataTypes from: " + manager.getName();

		Iterator<DataType> allDataTypes = manager.getAllDataTypes();
		while (allDataTypes.hasNext()) {
			monitor.checkCanceled();
			DataType dataType = allDataTypes.next();
			DataTypePath dataTypePath = dataType.getDataTypePath();
			String pathString = dataTypePath.toString();
			String htmlString = ToolTipUtils.getToolTipText(dataType);
			String plainString = HTMLUtilities.fromHTML(htmlString);
			fileWriter.append(pathString);
			fileWriter.append("\n");
			fileWriter.append(plainString);
			fileWriter.append("\n");
			fileWriter.append("------------------------------------------------------------\n");
		}
		fileWriter.close();

		message = "Results located in: " + dumpFile.getAbsoluteFile();
		monitor.setMessage(message);
		Msg.info(this, message);
	}

	private DataTypeManager userChooseDataTypeManager() {
		PluginTool tool = state.getTool();
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		DataTypeManager[] dataTypeManagers = service.getDataTypeManagers();
		String names[] = new String[dataTypeManagers.length];
		String initialDtmChoice = names[0];
		try {
			initialDtmChoice = currentProgram.getDataTypeManager().getName();
		}
		catch (Exception e) {
			// Ignore... assuming no program or dtm.
		}
		for (int i = 0; i < dataTypeManagers.length; i++) {
			names[i] = dataTypeManagers[i].getName();
		}
		String userChoice =
			OptionDialog.showInputChoiceDialog(null, "Choose a Data Type Manager or Cancel",
				"Choose", names, initialDtmChoice, OptionDialog.CANCEL_OPTION);
		if (userChoice == null) {
			return null;
		}
		for (int i = 0; i < dataTypeManagers.length; i++) {
			if (names[i].contentEquals(userChoice)) {
				return dataTypeManagers[i];
			}
		}
		return null; // should not reach this line.
	}

}
