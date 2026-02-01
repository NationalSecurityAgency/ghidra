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
package sarif.export.func;

import java.io.IOException;
import java.io.Writer;

import com.google.gson.JsonObject;

import ghidra.program.model.data.DataTypeManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ExtFunctionWriter  {

	protected JsonObject data = new JsonObject();

	public ExtFunctionWriter(DataTypeManager dtm, Writer baseWriter) throws IOException {
	}

	/**
	 * Exports all root types in the list as ISF JSON.
	 * 
	 * @param monitor the task monitor
	 * @return the resultant JSON object
	 * @throws IOException        if there is an exception writing the output
	 * @throws CancelledException if the action is cancelled by the user
	 */
	public JsonObject getRootObject(TaskMonitor monitor) throws IOException, CancelledException {
		genFunctions(monitor);
		return data;
	}

	private void genFunctions(TaskMonitor monitor) {
		// TODO Auto-generated method stub
		
	}
}
