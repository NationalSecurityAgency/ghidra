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
package sarif.export.data;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.ISF.IsfDataTypeWriter;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class ExtDataTypeWriterTask extends Task {

	private final DataTypeManager programDataTypeMgr;
	private final List<DataType> dataTypeList;
	private final File file;

	public ExtDataTypeWriterTask(DataTypeManager programDataTypeMgr, List<DataType> dataTypeList, File file) {
		super("Export Data Types", true, false, true);
		this.programDataTypeMgr = programDataTypeMgr;
		this.dataTypeList = dataTypeList;
		this.file = file;
	}

	@Override
	public void run(TaskMonitor monitor) {
		try {
			monitor.setMessage("Export to " + file.getName() + "...");
			IsfDataTypeWriter dataTypeWriter = new ExtIsfDataTypeWriter(programDataTypeMgr, dataTypeList, new FileWriter(file));

			try {
				dataTypeWriter.getRootObject(monitor);
				//dataTypeWriter.write(object);
			} finally {
				dataTypeWriter.close();
			}
		} catch (CancelledException e) {
			// user cancelled; ignore
		} catch (IOException e) {
			Msg.error("Export Data Types Failed", "Error exporting Data Types: " + e);
			return;
		}
	}
}
