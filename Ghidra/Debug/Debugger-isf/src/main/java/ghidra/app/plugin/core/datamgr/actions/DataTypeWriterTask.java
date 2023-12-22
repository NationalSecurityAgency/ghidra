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
package ghidra.app.plugin.core.datamgr.actions;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

import com.google.gson.JsonObject;

import docking.widgets.tree.GTree;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.ISF.IsfDataTypeWriter;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class DataTypeWriterTask extends Task {

	private final DataTypeManager programDataTypeMgr;
	private final List<DataType> dataTypeList;
	private final File file;
	private final GTree gTree;

	public DataTypeWriterTask(GTree gTree, DataTypeManager programDataTypeMgr, List<DataType> dataTypeList, File file) {
		super("Export Data Types", true, false, true);
		this.gTree = gTree;
		this.programDataTypeMgr = programDataTypeMgr;
		this.dataTypeList = dataTypeList;
		this.file = file;
	}

	@Override
	public void run(TaskMonitor monitor) {
		try {
			//monitor.setMessage("Export to " + file.getName() + "...");
			FileWriter baseWriter = file == null ? null : new FileWriter(file);
			IsfDataTypeWriter dataTypeWriter = new IsfDataTypeWriter(programDataTypeMgr, dataTypeList, baseWriter);

			try {
				JsonObject object = dataTypeWriter.getRootObject(monitor);
				if (file != null) {
					dataTypeWriter.write(object);
				}
			} finally {
				dataTypeWriter.close();
			}
		} catch (CancelledException e) {
			// user cancelled; ignore
		} catch (IOException e) {
			Msg.showError(getClass(), gTree, "Export Data Types Failed", "Error exporting Data Types: " + e);
			return;
		}
	}
}
