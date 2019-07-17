/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
//Example of a script prompting the user for a data type.
//@category Examples.Demo

import ghidra.app.script.GhidraScript;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

public class ChooseDataTypeScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		PluginTool tool = state.getTool();
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		DataTypeSelectionDialog selectionDialog =
			new DataTypeSelectionDialog(tool, dtm, -1, AllowedDataTypes.FIXED_LENGTH);
		tool.showDialog(selectionDialog);
		DataType dataType = selectionDialog.getUserChosenDataType();

		if (dataType != null) {
			println("Chosen data type: " + dataType);
		}
	}
}
