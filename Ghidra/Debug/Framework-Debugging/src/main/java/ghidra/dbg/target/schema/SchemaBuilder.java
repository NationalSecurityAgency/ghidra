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

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema.AttributeSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;

public class SchemaBuilder {
	private final DefaultSchemaContext context;
	private final SchemaName name;

	private Class<?> type = TargetObject.class;
	private Set<Class<? extends TargetObject>> interfaces = new LinkedHashSet<>();
	private boolean isCanonicalContainer = false;
	private Map<String, SchemaName> elementSchemas = new LinkedHashMap<>();
	private SchemaName defaultElementSchema = EnumerableTargetObjectSchema.OBJECT.getName();
	private Map<String, AttributeSchema> attributeSchemas = new LinkedHashMap<>();
	private AttributeSchema defaultAttributeSchema = AttributeSchema.DEFAULT_ANY;

	private Map<String, Object> elementOrigins = new LinkedHashMap<>();
	private Map<String, Object> attributeOrigins = new LinkedHashMap<>();

	public SchemaBuilder(DefaultSchemaContext context, SchemaName name) {
		this.context = context;
		this.name = name;
	}

	public SchemaBuilder setType(Class<?> type) {
		this.type = type;
		return this;
	}

	public Class<?> getType() {
		return type;
	}

	public SchemaBuilder setInterfaces(Set<Class<? extends TargetObject>> interfaces) {
		this.interfaces.clear();
		this.interfaces.addAll(interfaces);
		return this;
	}

	public Set<Class<? extends TargetObject>> getInterfaces() {
		return Set.copyOf(interfaces);
	}

	public SchemaBuilder addInterface(Class<? extends TargetObject> iface) {
		this.interfaces.add(iface);
		return this;
	}

	public SchemaBuilder setCanonicalContainer(boolean isCanonicalContainer) {
		this.isCanonicalContainer = isCanonicalContainer;
		return this;
	}

	public boolean isCanonicalContaineration() {
		return isCanonicalContainer;
	}

	public SchemaBuilder setElementSchemas(Map<String, SchemaName> elementSchemas) {
		this.elementSchemas.clear();
		this.elementSchemas.putAll(elementSchemas);
		return this;
	}

	/**
	 * Define the schema for a child element
	 * 
	 * @param index the index whose schema to define, or "" for the default
	 * @param schema the schema defining the element
	 * @return this builder
	 */
	public SchemaBuilder addElementSchema(String index, SchemaName schema, Object origin) {
		if (index.equals("")) {
			return setDefaultElementSchema(schema);
		}
		if (elementSchemas.containsKey(index)) {
			throw new IllegalArgumentException("Duplicate element index '" + index +
				"' origin1=" + elementOrigins.get(index) +
				" origin2=" + origin);
		}
		elementSchemas.put(index, schema);
		elementOrigins.put(index, origin);
		return this;
	}

	public Map<String, SchemaName> getElementSchemas() {
		return Map.copyOf(elementSchemas);
	}

	public SchemaBuilder setDefaultElementSchema(SchemaName defaultElementSchema) {
		this.defaultElementSchema = defaultElementSchema;
		return this;
	}

	public SchemaName getDefaultElementSchema() {
		return defaultElementSchema;
	}

	public SchemaBuilder setAttributeSchemas(Map<String, AttributeSchema> attributeSchemas) {
		this.attributeSchemas.clear();
		this.attributeSchemas.putAll(attributeSchemas);
		return this;
	}

	/**
	 * Define the schema for a child attribute.
	 * 
	 * <p>
	 * If the attribute schema's name is empty, the given schema becomes the default attribute
	 * schema.
	 * 
	 * @param schema the attribute schema to add to the definition
	 * @return this builder
	 */
	public SchemaBuilder addAttributeSchema(AttributeSchema schema, Object origin) {
		if (schema.getName().equals("")) {
			return setDefaultAttributeSchema(schema);
		}
		if (attributeSchemas.containsKey(schema.getName())) {
			throw new IllegalArgumentException("Duplicate attribute name '" + schema.getName() +
				"' origin1=" + attributeOrigins.get(schema.getName()) +
				" origin2=" + origin);
		}
		attributeSchemas.put(schema.getName(), schema);
		attributeOrigins.put(schema.getName(), origin);
		return this;
	}

	public Map<String, AttributeSchema> getAttributeSchemas() {
		return Map.copyOf(attributeSchemas);
	}

	public SchemaBuilder setDefaultAttributeSchema(AttributeSchema defaultAttributeSchema) {
		this.defaultAttributeSchema = defaultAttributeSchema;
		return this;
	}

	public AttributeSchema getDefaultAttributeSchema() {
		return defaultAttributeSchema;
	}

	public TargetObjectSchema buildAndAdd() {
		TargetObjectSchema schema = build();
		context.putSchema(schema);
		return schema;
	}

	public TargetObjectSchema build() {
		return new DefaultTargetObjectSchema(context, name, type, interfaces, isCanonicalContainer,
			elementSchemas, defaultElementSchema, attributeSchemas, defaultAttributeSchema);
	}
}
