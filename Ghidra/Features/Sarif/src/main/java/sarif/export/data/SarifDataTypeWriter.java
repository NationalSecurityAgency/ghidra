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

import java.io.IOException;
import java.io.Writer;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.ISF.IsfObject;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SarifDataTypeWriter extends ExtIsfDataTypeWriter {
	
	private JsonArray types = new JsonArray();

	public SarifDataTypeWriter(DataTypeManager dtm, List<DataType> target, Writer baseWriter) throws IOException {
		super(dtm, target, baseWriter);
		metadata = new JsonObject();
		baseTypes = types;
		userTypes = types;
		enums = types;
		functions = types;
		symbols = new JsonObject();
	}

	@Override
	protected void addSingletons() {
		add(baseTypes, "pointer", getTree(new SarifDataType(newTypedefPointer(null), this)));
		add(baseTypes, "undefined", getTree(new SarifDataType(newTypedefPointer(null), this)));
	}

	@Override
	protected JsonObject getObjectForDataType(DataType dt, TaskMonitor monitor)
			throws IOException, CancelledException {
		IsfObject isf = new SarifDataType(getIsfObject(dt, monitor), this);
		JsonObject jobj = (JsonObject) getTree(isf);
		resolved.put(dt, isf);
		return jobj;
	}

	public JsonArray getResults() {
		return types;
	}

}
