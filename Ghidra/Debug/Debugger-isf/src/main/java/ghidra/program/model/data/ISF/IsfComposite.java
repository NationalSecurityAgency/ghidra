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
package ghidra.program.model.data.ISF;

import java.util.*;

import com.google.gson.JsonObject;

import ghidra.program.model.data.*;
import ghidra.program.model.data.ISF.IsfDataTypeWriter.Exclude;
import ghidra.util.task.TaskMonitor;

public class IsfComposite implements IsfObject {

	public String kind;
	public Integer size;
	public JsonObject fields;

	@Exclude
	public int alignment;

	public IsfComposite(Composite composite, IsfDataTypeWriter writer, TaskMonitor monitor) {
		size = composite.getLength();
		kind = composite instanceof Structure ? "struct" : "union";
		alignment = composite.getAlignment();

		DataTypeComponent[] components = composite.getComponents();
		Map<String, DataTypeComponent> comps = new HashMap<>();
		for (DataTypeComponent component : components) {
			String key = component.getFieldName();
			if (key == null) {
				key = component.getDefaultFieldName();
			}
			comps.put(key, component);
		}
		ArrayList<String> keylist = new ArrayList<>(comps.keySet());
		Collections.sort(keylist);

		fields = new JsonObject();
		for (String key : keylist) {
			if (monitor.isCancelled()) {
				break;
			}

			DataTypeComponent component = comps.get(key);
			IsfObject type = writer.getObjectTypeDeclaration(component);
			IsfComponent cobj = new IsfComponent(component, type);
			fields.add(key, writer.getTree(cobj));
		}

	}

}
