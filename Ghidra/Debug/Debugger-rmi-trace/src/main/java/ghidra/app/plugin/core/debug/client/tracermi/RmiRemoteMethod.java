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

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;

public class RmiRemoteMethod {

	private final SchemaContext schemaContext;
	private String name;
	private String action;
	private String display;
	private String description;
	private RmiRemoteMethodParameter[] params;
	private TargetObjectSchema schema;
	private RmiMethods instance;
	private Method m;

	public RmiRemoteMethod(SchemaContext schemaContext, String name, String action, String display,
			String description, TargetObjectSchema schema, RmiMethods instance, Method m) {
		this.schemaContext = schemaContext;
		this.name = name;
		this.action = action;
		this.display = display;
		this.description = description;
		this.params = new RmiRemoteMethodParameter[m.getParameterCount()];
		this.schema = schema;
		this.instance = instance;
		this.m = m;

		int i = 0;
		for (Parameter p : m.getParameters()) {
			ParameterDescription<?> desc = TargetMethod.ParameterDescription.annotated(p);
			TargetObjectSchema pschema;
			if (desc.type != RmiTraceObject.class) {
				pschema = EnumerableTargetObjectSchema.schemaForPrimitive(desc.type);
			}
			else {
				pschema = schemaContext.getSchema(new SchemaName(desc.schema));
			}
			params[i++] = new RmiRemoteMethodParameter(desc.name, pschema, desc.required,
				desc.defaultValue, desc.display, desc.description);
		}
	}

	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}

	public String getAction() {
		return action;
	}

	public String getDisplay() {
		return display;
	}

	public RmiRemoteMethodParameter[] getParameters() {
		return params;
	}

	public Method getMethod() {
		return m;
	}

	public TargetObjectSchema getSchema() {
		return schema;
	}

	public RmiMethods getContainer() {
		return instance;
	}
}
