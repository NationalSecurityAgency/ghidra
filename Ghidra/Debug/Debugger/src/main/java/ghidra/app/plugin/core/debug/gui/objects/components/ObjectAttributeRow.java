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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.util.Map;

import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.dbg.target.TargetObject;

public class ObjectAttributeRow {

	private final TargetObject to;

	public ObjectAttributeRow(TargetObject to, DebuggerObjectsProvider provider) {
		this.to = to;
	}

	public TargetObject getTargetObject() {
		return to;
	}

	public String getName() {
		return to.getName();
	}

	public String getKind() {
		Map<String, ?> attributes = to.getCachedAttributes();
		Object object = attributes.get(TargetObject.KIND_ATTRIBUTE_NAME);
		if (object != null) {
			return (String) object;
		}
		return to.getTypeHint();
	}

	public String getValue() {
		Map<String, ?> attributes = to.getCachedAttributes();
		Object object = attributes.get(TargetObject.VALUE_ATTRIBUTE_NAME);
		if (object != null) {
			return (String) object;
		}
		return to.getDisplay();
	}

	public String getDisplay() {
		String value = to.getDisplay();
		if (value.indexOf(":") > 0) {
			value = value.substring(0, value.indexOf(":"));
		}
		return value;
	}

	public String getType() {
		Map<String, ?> attributes = to.getCachedAttributes();
		Object object = attributes.get(TargetObject.TYPE_ATTRIBUTE_NAME);
		if (object != null) {
			return (String) object;
		}
		return "";
	}

}
