/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import ghidra.dbg.target.schema.TargetObjectSchema.*;

/**
 * @deprecated This will be moved/refactored into trace database. In general, it will still exist,
 *             but things depending on it are now back on shifting sand.
 */
@Deprecated(since = "11.2")
public class SchemaBuilder {
	private final DefaultSchemaContext context;
	private final SchemaName name;

	private Class<?> type = TargetObject.class;
	private Set<Class<? extends TargetObject>> interfaces = new LinkedHashSet<>();
	private boolean isCanonicalContainer = false;

	private Map<String, SchemaName> elementSchemas = new LinkedHashMap<>();
	private SchemaName defaultElementSchema = EnumerableTargetObjectSchema.OBJECT.getName();
	private ResyncMode elementResync = TargetObjectSchema.DEFAULT_ELEMENT_RESYNC;

	private Map<String, AttributeSchema> attributeSchemas = new LinkedHashMap<>();
	private Map<String, String> attributeAliases = new LinkedHashMap<>();
	private AttributeSchema defaultAttributeSchema = AttributeSchema.DEFAULT_ANY;
	private ResyncMode attributeResync = TargetObjectSchema.DEFAULT_ATTRIBUTE_RESYNC;

	private Map<String, Object> elementOrigins = new LinkedHashMap<>();
	private Map<String, Object> attributeOrigins = new LinkedHashMap<>();

	public SchemaBuilder(DefaultSchemaContext context, SchemaName name) {
		this.context = context;
		this.name = name;
	}

	public SchemaBuilder(DefaultSchemaContext context, TargetObjectSchema schema) {
		this(context, schema.getName());
		setType(schema.getType());
		setInterfaces(schema.getInterfaces());
		setCanonicalContainer(schema.isCanonicalContainer());

		elementSchemas.putAll(schema.getElementSchemas());
		setDefaultElementSchema(schema.getDefaultElementSchema());
		setElementResyncMode(schema.getElementResyncMode());

		attributeSchemas.putAll(schema.getAttributeSchemas());
		setDefaultAttributeSchema(schema.getDefaultAttributeSchema());
		setAttributeResyncMode(schema.getAttributeResyncMode());
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

	public SchemaBuilder removeInterface(Class<? extends TargetObject> iface) {
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
			return setDefaultElementSchema(EnumerableTargetObjectSchema.OBJECT.getName());
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

	public SchemaBuilder setElementResyncMode(ResyncMode elementResync) {
		this.elementResync = elementResync;
		return this;
	}

	public ResyncMode getElementResyncMode() {
		return elementResync;
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

	public SchemaBuilder setAttributeResyncMode(ResyncMode attributeResync) {
		this.attributeResync = attributeResync;
		return this;
	}

	public ResyncMode getAttributeResyncMode() {
		return attributeResync;
	}

	public TargetObjectSchema buildAndAdd() {
		TargetObjectSchema schema = build();
		context.putSchema(schema);
		return schema;
	}

	public TargetObjectSchema build() {
		return new DefaultTargetObjectSchema(
			context, name, type, interfaces, isCanonicalContainer,
			elementSchemas, defaultElementSchema, elementResync,
			attributeSchemas, attributeAliases, defaultAttributeSchema, attributeResync);
	}
}
