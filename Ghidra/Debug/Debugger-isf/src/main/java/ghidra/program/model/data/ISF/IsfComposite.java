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

import com.google.gson.JsonObject;

import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.util.task.TaskMonitor;

public class IsfComposite extends AbstractIsfObject {

	public String kind;
	public Integer size;
	public JsonObject fields;
	
	public IsfComposite(Composite composite, IsfDataTypeWriter writer, TaskMonitor monitor) {
		super(composite);
		size = composite.getLength();
		kind = composite instanceof Structure ? "struct" : "union";

		DataTypeComponent[] components = composite.getComponents();
		if (components.length == 0) {
			// NB: composite.getLength always returns > 0
			size = 0;
		}
		fields = new JsonObject();
		for (DataTypeComponent component : components) {
			if (monitor.isCancelled()) {
				break;
			}

			IsfObject type = writer.getObjectTypeDeclaration(component);
			IsfComponent cobj = getComponent(component, type);
			String key = component.getFieldName();
			if (key == null) {
				key = DataTypeComponent.DEFAULT_FIELD_NAME_PREFIX + component.getOrdinal();
				if (component.getParent() instanceof Structure) {
					key += "_0x" + Integer.toHexString(component.getOffset());
				}
			}
			fields.add(key, writer.getTree(cobj));
		}
	}

	protected IsfComponent getComponent(DataTypeComponent component, IsfObject type) {
		return new IsfComponent(component, type);
	}

}
