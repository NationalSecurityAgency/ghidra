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
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.rmi.trace.TraceRmi.Value;

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

	public RmiRemoteMethod(SchemaContext schemaContext, String name, String action, String display, String description, TargetObjectSchema schema, RmiMethods instance, Method m) {
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
			TargetObjectSchema pschema = getSchemaFromParameter(p);
			String pname = p.getName(); // NB: don't change this unless yuou resolve the ordering issues
			String pdesc = pname;
			String pdisp = pname;
			if (i == 0) {
				RmiMethodRegistry.TraceMethod annot = m.getAnnotation(RmiMethodRegistry.TraceMethod.class);
				if (annot != null) {
					pschema = schemaContext.getSchema(new SchemaName(annot.schema()));
				}
				pdisp = "Object";
			}
			Value pdef = null;
			TargetMethod.Param pannot = p.getAnnotation(TargetMethod.Param.class);
			if (pannot != null) {
				pdesc = pannot.description();
				pdisp = pannot.display();
			}
			boolean required = i != 0;
			params[i++] = new RmiRemoteMethodParameter(pname, pschema, required, pdef, pdisp, pdesc);
		}
	}

	private TargetObjectSchema getSchemaFromParameter(Parameter p) {
		if (p.getAnnotatedType().getType().equals(String.class)) {
			 return EnumerableTargetObjectSchema.STRING;
		}
		if (p.getAnnotatedType().getType().equals(Boolean.class)) {
			 return EnumerableTargetObjectSchema.BOOL;
		}
		if (p.getAnnotatedType().getType().equals(Integer.class)) {
			 return EnumerableTargetObjectSchema.INT;
		}
		if (p.getAnnotatedType().getType().equals(Long.class)) {
			 return EnumerableTargetObjectSchema.LONG;
		}
		if (p.getAnnotatedType().getType().equals(Address.class)) {
			 return EnumerableTargetObjectSchema.ADDRESS;
		}
		if (p.getAnnotatedType().getType().equals(AddressRange.class)) {
			 return EnumerableTargetObjectSchema.RANGE;
		}
		 return EnumerableTargetObjectSchema.ANY;
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
