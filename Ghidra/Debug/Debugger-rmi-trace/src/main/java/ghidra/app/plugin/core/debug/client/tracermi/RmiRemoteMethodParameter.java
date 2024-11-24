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
package ghidra.app.plugin.core.debug.client.tracermi;

import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.rmi.trace.TraceRmi.*;

public class RmiRemoteMethodParameter {

	private final String name;
	private final TargetObjectSchema schema;
	private final boolean required;
	private final Object defaultValue;
	private final String display;
	private final String description;

	public RmiRemoteMethodParameter(String name, TargetObjectSchema schema, boolean required,
			Object defaultValue, String display, String description) {
		this.name = name;
		this.schema = schema;
		this.required = required;
		this.defaultValue = defaultValue;
		this.display = display;
		this.description = description;
	}

	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}

	public String getDisplay() {
		return display;
	}

	public ValueType getType() {
		String schemaName = schema.getName().toString();
//		if (schemaName.equals("ANY")) {
//			return ValueType.newBuilder().setName("OBJECT").build();
//		}
		return ValueType.newBuilder().setName(schemaName).build();
	}

	public Object getDefaultValue() {
		return defaultValue;
	}

	public boolean isRequired() {
		return required;
	}
}
