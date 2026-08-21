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
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;

/**
 * The "type descriptor" of a {@link TraceObject}.
 * 
 * <p>
 * These are typically loaded from XML anymore. See {@link XmlSchemaContext}. It typically consists
 * of a list of expected attributes and their respective schemas, some of which may be
 * {@link PrimitiveTraceObjectSchema primitive}; and the schema of elements, if this is a container.
 * It is a bit more flexible than that, but that is the usual case. A schema may also specify one or
 * more interfaces it supports. An interface typically requires certain attributes, but also implies
 * some debugger-related behavior should be available via the target's command set. See
 * {@link TraceObjectInterface} and its derivatives for information about each interface.
 */
public class DefaultTraceObjectSchema
		implements TraceObjectSchema, Comparable<DefaultTraceObjectSchema> {
	private static final String INDENT = "  ";

	public static class DefaultAttributeSchema
			implements AttributeSchema, Comparable<DefaultAttributeSchema> {
		private final String name;
		private final SchemaName schema;
		private final boolean isRequired;
		private final boolean isFixed;
		private final Hidden hidden;

		public DefaultAttributeSchema(String name, SchemaName schema, boolean isRequired,
				boolean isFixed, Hidden hidden) {
			if (name.equals("") && isRequired) {
				throw new IllegalArgumentException(
					"The default attribute schema cannot be required");
			}
			this.name = name;
			this.schema = schema;
			this.isRequired = isRequired;
			this.isFixed = isFixed;
			this.hidden = hidden.adjust(name);
		}

		@Override
		public String toString() {
			return String.format("<attr name=%s schema=%s required=%s fixed=%s hidden=%s>",
				name, schema, isRequired, isFixed, hidden.toString().toLowerCase());
		}

		/**
		 * {@inheritDoc}
		 * 
		 * <p>
		 * Generally speaking, object identity is sufficient for checking equality in production;
		 * however, this method is provided for testing equality between an actual and expected
		 * attribute schema.
		 */
		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof DefaultAttributeSchema that)) {
				return false;
			}
			if (!Objects.equals(this.name, that.name)) {
				return false;
			}
			if (!Objects.equals(this.schema, that.schema)) {
				return false;
			}
			if (this.isRequired != that.isRequired) {
				return false;
			}
			if (this.isFixed != that.isFixed) {
				return false;
			}
			if (this.hidden != that.hidden) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			return name.hashCode();
		}

		@Override
		public int compareTo(DefaultAttributeSchema o) {
			return name.compareTo(o.name);
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public SchemaName getSchema() {
			return schema;
		}

		@Override
		public boolean isRequired() {
			return isRequired;
		}

		@Override
		public boolean isFixed() {
			return isFixed;
		}

		@Override
		public Hidden getHidden() {
			return hidden;
		}
	}

	protected static class AliasResolver {
		private final Map<String, AttributeSchema> schemas;
		private final Map<String, String> aliases;
		private final AttributeSchema defaultSchema;
		private Map<String, String> resolvedAliases;

		public AliasResolver(Map<String, AttributeSchema> schemas, Map<String, String> aliases,
				AttributeSchema defaultSchema) {
			this.schemas = schemas;
			this.aliases = aliases;
			this.defaultSchema = defaultSchema;
		}

		public Map<String, String> resolveAliases() {
			this.resolvedAliases = new LinkedHashMap<>();
			for (String alias : aliases.keySet()) {
				if (alias.equals("")) {
					throw new IllegalArgumentException("Key '' cannot be an alias");
				}
				if (schemas.containsKey(alias)) {
					throw new IllegalArgumentException(
						"Key '%s' cannot be both an attribute and an alias".formatted(alias));
				}
				resolveAlias(alias, new LinkedHashSet<>());
			}
			return resolvedAliases;
		}

		protected String resolveAlias(String alias, LinkedHashSet<String> visited) {
			String already = resolvedAliases.get(alias);
			if (already != null) {
				return already;
			}
			if (!visited.add(alias)) {
				throw new IllegalArgumentException("Cycle of aliases: " + visited);
			}
			String to = aliases.get(alias);
			if (to == null) {
				return alias;
			}
			if (to.equals("")) {
				throw new IllegalArgumentException(
					"Cannot alias to key '' (from %s)".formatted(alias));
			}
			String result = resolveAlias(to, visited);
			resolvedAliases.put(alias, result);
			return result;
		}

		public Map<String, AttributeSchema> resolveSchemas() {
			Map<String, AttributeSchema> resolved = new LinkedHashMap<>(schemas);
			for (Map.Entry<String, String> ent : resolvedAliases.entrySet()) {
				resolved.put(ent.getKey(), schemas.getOrDefault(ent.getValue(), defaultSchema));
			}
			return resolved;
		}
	}

	private final SchemaContext context;
	private final SchemaName name;
	private final Class<?> type;
	private final Set<Class<? extends TraceObjectInterface>> interfaces;
	private final boolean isCanonicalContainer;

	private final Map<String, SchemaName> elementSchemas;
	private final SchemaName defaultElementSchema;

	private final Map<String, AttributeSchema> attributeSchemas;
	private final Map<String, String> attributeAliases;
	private final AttributeSchema defaultAttributeSchema;

	DefaultTraceObjectSchema(SchemaContext context, SchemaName name, Class<?> type,
			Set<Class<? extends TraceObjectInterface>> interfaces, boolean isCanonicalContainer,
			Map<String, SchemaName> elementSchemas, SchemaName defaultElementSchema,
			Map<String, AttributeSchema> attributeSchemas, Map<String, String> attributeAliases,
			AttributeSchema defaultAttributeSchema) {
		this.context = context;
		this.name = name;
		this.type = type;
		this.interfaces = Collections.unmodifiableSet(new LinkedHashSet<>(interfaces));
		this.isCanonicalContainer = isCanonicalContainer;

		this.elementSchemas = Collections.unmodifiableMap(new LinkedHashMap<>(elementSchemas));
		this.defaultElementSchema = defaultElementSchema;

		AliasResolver resolver =
			new AliasResolver(attributeSchemas, attributeAliases, defaultAttributeSchema);
		this.attributeAliases = Collections.unmodifiableMap(resolver.resolveAliases());
		this.attributeSchemas = Collections.unmodifiableMap(resolver.resolveSchemas());
		this.defaultAttributeSchema = defaultAttributeSchema;
	}

	@Override
	public SchemaContext getContext() {
		return context;
	}

	@Override
	public SchemaName getName() {
		return name;
	}

	@Override
	public Class<?> getType() {
		return type;
	}

	@Override
	public Set<Class<? extends TraceObjectInterface>> getInterfaces() {
		return interfaces;
	}

	@Override
	public boolean isCanonicalContainer() {
		return isCanonicalContainer;
	}

	@Override
	public Map<String, SchemaName> getElementSchemas() {
		return elementSchemas;
	}

	@Override
	public SchemaName getDefaultElementSchema() {
		return defaultElementSchema;
	}

	@Override
	public Map<String, AttributeSchema> getAttributeSchemas() {
		return attributeSchemas;
	}

	@Override
	public Map<String, String> getAttributeAliases() {
		return attributeAliases;
	}

	@Override
	public AttributeSchema getDefaultAttributeSchema() {
		return defaultAttributeSchema;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		toString(sb);
		return sb.toString();
	}

	protected void toString(StringBuilder sb) {
		sb.append("schema ");
		sb.append(name);
		if (isCanonicalContainer) {
			sb.append("*");
		}
		sb.append(" {\n" + INDENT);
		sb.append("ifaces = [");
		for (Class<? extends TraceObjectInterface> iface : interfaces) {
			sb.append(TraceObjectInterfaceUtils.getSchemaName(iface));
			sb.append(" ");
		}
		sb.append("]\n" + INDENT);
		sb.append("elements = ");
		sb.append(elementSchemas);
		sb.append(" default " + defaultElementSchema);
		sb.append("\n" + INDENT);
		sb.append("attributes = ");
		sb.append(attributeSchemas);
		sb.append(" default " + defaultAttributeSchema);
		sb.append(" aliases " + attributeAliases);
		sb.append("\n}");
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Generally speaking, object identity is sufficient for checking equality in production;
	 * however, this method is provided for testing equality between an actual and expected schema.
	 * Furthermore, this tests more for "content equality" than it does schema equivalence. In
	 * particular, if the two entries being compared come from different contexts, then, even though
	 * they may refer to child schemas by the same name, those child schemas may not be equivalent.
	 * This test will consider them "equal," even though they specify different overall schemas.
	 * Testing for true equivalence has too many nuances to consider here: What if they come from
	 * different contexts? What if they refer to different schemas, but those schemas are
	 * equivalent? etc.
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof DefaultTraceObjectSchema that)) {
			return false;
		}
		if (!Objects.equals(this.name, that.name)) {
			return false;
		}
		if (!Objects.equals(this.type, that.type)) {
			return false;
		}
		if (!Objects.equals(this.interfaces, that.interfaces)) {
			return false;
		}
		if (this.isCanonicalContainer != that.isCanonicalContainer) {
			return false;
		}
		if (!Objects.equals(this.elementSchemas, that.elementSchemas)) {
			return false;
		}
		if (!Objects.equals(this.defaultElementSchema, that.defaultElementSchema)) {
			return false;
		}
		if (!Objects.equals(this.attributeSchemas, that.attributeSchemas)) {
			return false;
		}
		if (!Objects.equals(this.attributeAliases, that.attributeAliases)) {
			return false;
		}
		if (!Objects.equals(this.defaultAttributeSchema, that.defaultAttributeSchema)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public int compareTo(DefaultTraceObjectSchema o) {
		return name.compareTo(o.name);
	}
}
