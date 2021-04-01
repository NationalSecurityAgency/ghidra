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
package ghidra.dbg.target.schema;

import java.util.*;

import ghidra.dbg.attributes.TargetDataType;
import ghidra.dbg.attributes.TargetObjectList;
import ghidra.dbg.target.TargetAttacher.TargetAttachKindSet;
import ghidra.dbg.target.TargetBreakpointSpecContainer.TargetBreakpointKindSet;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSteppable.TargetStepKindSet;
import ghidra.dbg.util.PathMatcher;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

public enum EnumerableTargetObjectSchema implements TargetObjectSchema {
	/**
	 * The top-most type descriptor
	 * 
	 * <p>
	 * The described value can be any primitive or a {@link TargetObject}.
	 */
	ANY("ANY", Object.class) {
		@Override
		public SchemaName getDefaultElementSchema() {
			return OBJECT.getName();
		}

		@Override
		public AttributeSchema getDefaultAttributeSchema() {
			return AttributeSchema.DEFAULT_ANY;
		}
	},
	/**
	 * The least restrictive, but least informative object schema.
	 * 
	 * <p>
	 * This requires nothing more than the described value to be a {@link TargetObject}.
	 */
	OBJECT("OBJECT", TargetObject.class) {
		@Override
		public SchemaName getDefaultElementSchema() {
			return OBJECT.getName();
		}

		@Override
		public AttributeSchema getDefaultAttributeSchema() {
			return AttributeSchema.DEFAULT_ANY;
		}
	},
	/**
	 * A type so restrictive nothing can satisfy it.
	 * 
	 * <p>
	 * This is how a schema specifies that a particular key is not allowed. It is commonly used as
	 * the default attribute when only certain enumerated attributes are allowed. It is also used as
	 * the type for the children of primitives, since primitives cannot have successors.
	 */
	VOID("VOID", Void.class, void.class),
	BOOL("BOOL", Boolean.class, boolean.class),
	BYTE("BYTE", Byte.class, byte.class),
	SHORT("SHORT", Short.class, short.class),
	INT("INT", Integer.class, int.class),
	LONG("LONG", Long.class, long.class),
	STRING("STRING", String.class),
	ADDRESS("ADDRESS", Address.class),
	RANGE("RANGE", AddressRange.class),
	DATA_TYPE("DATA_TYPE", TargetDataType.class),
	LIST_OBJECT("LIST_OBJECT", TargetObjectList.class),
	MAP_PARAMETERS("MAP_PARAMETERS", TargetParameterMap.class),
	SET_ATTACH_KIND("SET_ATTACH_KIND", TargetAttachKindSet.class), // TODO: Limited built-in generics
	SET_BREAKPOINT_KIND("SET_BREAKPOINT_KIND", TargetBreakpointKindSet.class),
	SET_STEP_KIND("SET_STEP_KIND", TargetStepKindSet.class),
	EXECUTION_STATE("EXECUTION_STATE", TargetExecutionState.class);

	public static final class MinimalSchemaContext extends DefaultSchemaContext {
		public static final SchemaContext INSTANCE = new MinimalSchemaContext();
	}

	/**
	 * Get a suitable schema for a given Java primitive class
	 * 
	 * <p>
	 * The term "primitive" here is used in terms of object schemas, not in terms of Java types.
	 * 
	 * @param cls the class, which may or may not be the boxed form
	 * @return the schema or null if no schema is suitable
	 */
	public static EnumerableTargetObjectSchema schemaForPrimitive(Class<?> cls) {
		for (EnumerableTargetObjectSchema schema : EnumerableTargetObjectSchema.values()) {
			if (schema.getTypes().contains(cls)) {
				return schema;
			}
		}
		return null;
	}

	/**
	 * Get the name of a suitable enumerable schema for a given Java class
	 * 
	 * @see #schemaForPrimitive(Class)
	 * @param cls the class, which may or may no be the boxed form
	 * @return the name or null if no schema is suitable
	 */
	public static SchemaName nameForPrimitive(Class<?> cls) {
		EnumerableTargetObjectSchema schema = schemaForPrimitive(cls);
		return schema == null ? null : schema.getName();
	}

	private final SchemaName name;
	private final List<Class<?>> types;

	private EnumerableTargetObjectSchema(String name, Class<?>... types) {
		this.name = new SchemaName(name);
		this.types = List.of(types);
	}

	@Override
	public SchemaContext getContext() {
		return MinimalSchemaContext.INSTANCE;
	}

	@Override
	public SchemaName getName() {
		return name;
	}

	@Override
	public Class<?> getType() {
		return types.get(0);
	}

	public List<Class<?>> getTypes() {
		return types;
	}

	@Override
	public Set<Class<? extends TargetObject>> getInterfaces() {
		return Set.of();
	}

	@Override
	public boolean isCanonicalContainer() {
		return false;
	}

	@Override
	public Map<String, SchemaName> getElementSchemas() {
		return Map.of();
	}

	@Override
	public SchemaName getDefaultElementSchema() {
		return VOID.getName();
	}

	@Override
	public ResyncMode getElementResyncMode() {
		return TargetObjectSchema.DEFAULT_ELEMENT_RESYNC;
	}

	@Override
	public Map<String, AttributeSchema> getAttributeSchemas() {
		return Map.of();
	}

	@Override
	public AttributeSchema getDefaultAttributeSchema() {
		return AttributeSchema.DEFAULT_VOID;
	}

	@Override
	public ResyncMode getAttributeResyncMode() {
		return TargetObjectSchema.DEFAULT_ATTRIBUTE_RESYNC;
	}

	@Override
	public PathMatcher searchFor(Class<? extends TargetObject> type, boolean requireCanonical) {
		return new PathMatcher();
	}

	@Override
	public List<String> searchForCanonicalContainer(Class<? extends TargetObject> type) {
		return null;
	}

	@Override
	public List<String> searchForSuitable(Class<? extends TargetObject> type, List<String> path) {
		return null;
	}
}
