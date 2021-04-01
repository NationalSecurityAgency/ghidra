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

import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;

public class DefaultTargetObjectSchema
		implements TargetObjectSchema, Comparable<DefaultTargetObjectSchema> {
	private static final String INDENT = "  ";

	protected static class DefaultAttributeSchema
			implements AttributeSchema, Comparable<DefaultAttributeSchema> {
		private final String name;
		private final SchemaName schema;
		private final boolean isRequired;
		private final boolean isFixed;
		private final boolean isHidden;

		public DefaultAttributeSchema(String name, SchemaName schema, boolean isRequired,
				boolean isFixed, boolean isHidden) {
			if (name.equals("") && isRequired) {
				throw new IllegalArgumentException(
					"The default attribute schema cannot be required");
			}
			this.name = name;
			this.schema = schema;
			this.isRequired = isRequired;
			this.isFixed = isFixed;
			this.isHidden = isHidden;
		}

		@Override
		public String toString() {
			return String.format("<attr name=%s schema=%s required=%s fixed=%s hidden=%s>",
				name, schema, isRequired, isFixed, isHidden);
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
			if (!(obj instanceof DefaultAttributeSchema)) {
				return false;
			}
			DefaultAttributeSchema that = (DefaultAttributeSchema) obj;
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
			if (this.isHidden != that.isHidden) {
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
		public boolean isHidden() {
			return isHidden;
		}
	}

	private final SchemaContext context;
	private final SchemaName name;
	private final Class<?> type;
	private final Set<Class<? extends TargetObject>> interfaces;
	private final boolean isCanonicalContainer;

	private final Map<String, SchemaName> elementSchemas;
	private final SchemaName defaultElementSchema;
	private final ResyncMode elementResync;

	private final Map<String, AttributeSchema> attributeSchemas;
	private final AttributeSchema defaultAttributeSchema;
	private final ResyncMode attributeResync;

	DefaultTargetObjectSchema(SchemaContext context, SchemaName name, Class<?> type,
			Set<Class<? extends TargetObject>> interfaces, boolean isCanonicalContainer,
			Map<String, SchemaName> elementSchemas, SchemaName defaultElementSchema,
			ResyncMode elementResync,
			Map<String, AttributeSchema> attributeSchemas, AttributeSchema defaultAttributeSchema,
			ResyncMode attributeResync) {
		this.context = context;
		this.name = name;
		this.type = type;
		this.interfaces = Collections.unmodifiableSet(new LinkedHashSet<>(interfaces));
		this.isCanonicalContainer = isCanonicalContainer;

		this.elementSchemas = Collections.unmodifiableMap(new LinkedHashMap<>(elementSchemas));
		this.defaultElementSchema = defaultElementSchema;
		this.elementResync = elementResync;

		this.attributeSchemas = Collections.unmodifiableMap(new LinkedHashMap<>(attributeSchemas));
		this.defaultAttributeSchema = defaultAttributeSchema;
		this.attributeResync = attributeResync;
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
	public Set<Class<? extends TargetObject>> getInterfaces() {
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
	public ResyncMode getElementResyncMode() {
		return elementResync;
	}

	@Override
	public Map<String, AttributeSchema> getAttributeSchemas() {
		return attributeSchemas;
	}

	@Override
	public AttributeSchema getDefaultAttributeSchema() {
		return defaultAttributeSchema;
	}

	@Override
	public ResyncMode getAttributeResyncMode() {
		return attributeResync;
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
		for (Class<? extends TargetObject> iface : interfaces) {
			sb.append(DebuggerObjectModel.requireIfaceName(iface));
			sb.append(" ");
		}
		sb.append("]\n" + INDENT);
		sb.append("elements(resync " + elementResync + ") = ");
		sb.append(elementSchemas);
		sb.append(" default " + defaultElementSchema);
		sb.append("\n" + INDENT);
		sb.append("attributes(resync " + attributeResync + ") = ");
		sb.append(attributeSchemas);
		sb.append(" default " + defaultAttributeSchema);
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
		if (!(obj instanceof DefaultTargetObjectSchema)) {
			return false;
		}
		DefaultTargetObjectSchema that = (DefaultTargetObjectSchema) obj;
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
		if (!Objects.equals(this.elementResync, that.elementResync)) {
			return false;
		}
		if (!Objects.equals(this.attributeSchemas, that.attributeSchemas)) {
			return false;
		}
		if (!Objects.equals(this.defaultAttributeSchema, that.defaultAttributeSchema)) {
			return false;
		}
		if (!Objects.equals(this.attributeResync, that.attributeResync)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public int compareTo(DefaultTargetObjectSchema o) {
		return name.compareTo(o.name);
	}
}
