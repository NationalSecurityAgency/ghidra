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
//An example script that shows a few methods for printing a structure, including a nested 
//printing of structures that contain other structures
//@category Examples
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.ToolTipUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;

public class PrintStructureScript extends GhidraScript {

	@Override
	protected void run() throws Exception {

		String dtName = "/crtdefs.h/_struct_9";
		DataType dataType = findDataTypeByName(dtName);
		if (dataType == null) {
			println("Could not find data type by name: " + dtName);
			return;
		}

		String toolTipText = ToolTipUtils.getToolTipText(dataType);
		println("Data type tooltip (HTML): " + toolTipText);

		println("Data type text (non-HTML): " + dataType);

		printStructure(dataType);
	}

	private void printStructure(DataType dataType) {
		StringBuilder buffer = new StringBuilder();
		printStructureRecursively(dataType, buffer, 0);
		println("\n" + buffer.toString());
	}

	private void printStructureRecursively(DataType dataType, StringBuilder buffer, int level) {
		if (!(dataType instanceof Structure)) {
			println("Data type is not a structure: " + dataType);
			return;
		}

		Structure structure = (Structure) dataType;
		tabs(buffer, level - 1);
		buffer.append("Structure ").append(structure.getName()).append(" {\n");

		DataTypeComponent[] components = structure.getComponents();
		for (DataTypeComponent component : components) {
			DataType componentDataType = component.getDataType();
			if (componentDataType instanceof Structure) {
				printStructureRecursively(componentDataType, buffer, level + 1);
			}
			else {
				tabs(buffer, level);

				DataType childType = componentDataType;
				buffer.append(childType.getName());
				buffer.append('\t');
				buffer.append(childType.getLength()).append('\n');
			}
		}

		tabs(buffer, level - 1);
		buffer.append("}\n");

		tabs(buffer, level - 1);
		buffer.append(
			"Size=" + structure.getLength() + " Actual Alignment=" + structure.getAlignment()).append(
			'\n');
	}

	private void tabs(StringBuilder buffer, int level) {
		for (int i = 0; i < level + 1; i++) {
			buffer.append('\t');
		}
	}

	private DataType findDataTypeByName(String name) {
		PluginTool tool = state.getTool();
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		DataTypeManager[] dataTypeManagers = service.getDataTypeManagers();
		for (DataTypeManager manager : dataTypeManagers) {
			DataType dataType = manager.getDataType(name);
			if (dataType != null) {
				return dataType;
			}
		}
		return null;
	}
}
