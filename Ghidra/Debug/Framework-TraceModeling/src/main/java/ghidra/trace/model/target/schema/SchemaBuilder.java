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
package ghidra.trace.model.target.schema;

import java.util.*;

import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.schema.TraceObjectSchema.AttributeSchema;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;

/**
 * A builder for a {@link TraceObjectSchema}.
 */
public class SchemaBuilder {
	public static final SchemaName DEFAULT_ELEMENT_SCHEMA =
		PrimitiveTraceObjectSchema.OBJECT.getName();
	public static final AttributeSchema DEFAULT_ATTRIBUTE_SCHEMA = AttributeSchema.DEFAULT_ANY;

	private final DefaultSchemaContext context;
	private final SchemaName name;

	private Class<?> type = TraceObject.class;
	private Set<Class<? extends TraceObjectInterface>> interfaces = new LinkedHashSet<>();
	private boolean isCanonicalContainer = false;

	private Map<String, SchemaName> elementSchemas = new LinkedHashMap<>();
	private SchemaName defaultElementSchema = DEFAULT_ELEMENT_SCHEMA;

	private Map<String, AttributeSchema> attributeSchemas = new LinkedHashMap<>();
	private Map<String, String> attributeAliases = new LinkedHashMap<>();
	private AttributeSchema defaultAttributeSchema = DEFAULT_ATTRIBUTE_SCHEMA;

	private Map<String, Object> elementOrigins = new LinkedHashMap<>();
	private Map<String, Object> attributeOrigins = new LinkedHashMap<>();

	public SchemaBuilder(DefaultSchemaContext context, SchemaName name) {
		this.context = context;
		this.name = name;
	}

	public SchemaBuilder(DefaultSchemaContext context, TraceObjectSchema schema) {
		this(context, schema.getName());
		setType(schema.getType());
		setInterfaces(schema.getInterfaces());
		setCanonicalContainer(schema.isCanonicalContainer());

		elementSchemas.putAll(schema.getElementSchemas());
		setDefaultElementSchema(schema.getDefaultElementSchema());

		attributeSchemas.putAll(schema.getAttributeSchemas());
		setDefaultAttributeSchema(schema.getDefaultAttributeSchema());
	}

	public SchemaBuilder setType(Class<?> type) {
		this.type = type;
		return this;
	}

	public Class<?> getType() {
		return type;
	}

	public SchemaBuilder setInterfaces(Set<Class<? extends TraceObjectInterface>> interfaces) {
		this.interfaces.clear();
		this.interfaces.addAll(interfaces);
		return this;
	}

	public Set<Class<? extends TraceObjectInterface>> getInterfaces() {
		return Set.copyOf(interfaces);
	}

	public SchemaBuilder addInterface(Class<? extends TraceObjectInterface> iface) {
		this.interfaces.add(iface);
		return this;
	}

	public SchemaBuilder removeInterface(Class<? extends TraceObjectInterface> iface) {
		this.interfaces.remove(iface);
		return this;
	}

	public SchemaBuilder setCanonicalContainer(boolean isCanonicalContainer) {
		this.isCanonicalContainer = isCanonicalContainer;
		return this;
	}

	public boolean isCanonicalContaineration() {
		return isCanonicalContainer;
	}

	/**
	 * Define the schema for a child element
	 * 
	 * @param index the index whose schema to define, or "" for the default
	 * @param schema the schema defining the element
	 * @param origin optional, for diagnostics, an object describing the element schema's origin
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

	public SchemaBuilder removeElementSchema(String index) {
		if (index.equals("")) {
			return setDefaultElementSchema(PrimitiveTraceObjectSchema.OBJECT.getName());
		}
		elementSchemas.remove(index);
		elementOrigins.remove(index);
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

	/**
	 * Define the schema for a child attribute.
	 * 
	 * <p>
	 * If the attribute schema's name is empty, the given schema becomes the default attribute
	 * schema.
	 * 
	 * @param schema the attribute schema to add to the definition
	 * @param origin optional, for diagnostics, an object describing the attribute schema's origin
	 * @return this builder
	 */
	public SchemaBuilder addAttributeSchema(AttributeSchema schema, Object origin) {
		if (schema.getName().equals("")) {
			return setDefaultAttributeSchema(schema);
		}
		if (attributeOrigins.containsKey(schema.getName())) {
			throw new IllegalArgumentException(
				"Duplicate attribute name '%s' adding schema origin1=%s origin2=%s".formatted(
					schema.getName(), attributeOrigins.get(schema.getName()), origin));
		}
		attributeSchemas.put(schema.getName(), schema);
		attributeOrigins.put(schema.getName(), origin);
		return this;
	}

	public SchemaBuilder removeAttributeSchema(String name) {
		if (name.equals("")) {
			return setDefaultAttributeSchema(AttributeSchema.DEFAULT_ANY);
		}
		attributeSchemas.remove(name);
		attributeAliases.remove(name);
		attributeOrigins.remove(name);
		return this;
	}

	public Map<String, AttributeSchema> getAttributeSchemas() {
		return Map.copyOf(attributeSchemas);
	}

	public AttributeSchema getAttributeSchema(String name) {
		return attributeSchemas.get(name);
	}

	public SchemaBuilder replaceAttributeSchema(AttributeSchema schema, Object origin) {
		if (schema.getName().equals("")) {
			return setDefaultAttributeSchema(schema);
		}
		attributeAliases.remove(schema.getName());
		attributeSchemas.put(schema.getName(), schema);
		attributeOrigins.put(schema.getName(), origin);
		return this;
	}

	protected void validateAlias(String from, String to) {
		if (from.equals("")) {
			throw new IllegalArgumentException("Key '' cannot be an alias");
		}
		if (to.equals("")) {
			throw new IllegalArgumentException("Cannot alias to key '' (from %s)".formatted(from));
		}
	}

	public SchemaBuilder addAttributeAlias(String from, String to, Object origin) {
		validateAlias(from, to);
		if (attributeOrigins.containsKey(from)) {
			throw new IllegalArgumentException(
				"Duplicate attribute name '%s' adding alias origin1=%s origin2=%s".formatted(
					from, attributeOrigins.get(from), origin));
		}
		attributeAliases.put(from, to);
		attributeOrigins.put(from, origin);
		return this;
	}

	public SchemaBuilder replaceAttributeAlias(String from, String to, Object origin) {
		validateAlias(from, to);
		attributeSchemas.remove(from);
		attributeAliases.put(from, to);
		attributeOrigins.put(from, origin);
		return this;
	}

	public SchemaBuilder setDefaultAttributeSchema(AttributeSchema defaultAttributeSchema) {
		this.defaultAttributeSchema = defaultAttributeSchema;
		return this;
	}

	public AttributeSchema getDefaultAttributeSchema() {
		return defaultAttributeSchema;
	}

	public TraceObjectSchema buildAndAdd() {
		TraceObjectSchema schema = build();
		context.putSchema(schema);
		return schema;
	}

	public TraceObjectSchema buildAndReplace() {
		TraceObjectSchema schema = build();
		context.replaceSchema(schema);
		return schema;
	}

	public TraceObjectSchema build() {
		return new DefaultTraceObjectSchema(
			context, name, type, interfaces, isCanonicalContainer,
			elementSchemas, defaultElementSchema,
			attributeSchemas, attributeAliases, defaultAttributeSchema);
	}
}
