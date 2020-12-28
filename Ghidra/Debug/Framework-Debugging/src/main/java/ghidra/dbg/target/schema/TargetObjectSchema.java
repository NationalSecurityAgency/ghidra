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
import java.util.Map.Entry;
import java.util.stream.Collectors;

import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.DefaultTargetObjectSchema.DefaultAttributeSchema;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;

/**
 * Type information for a particular value or {@link TargetObject}
 * 
 * <p>
 * This allows a client to inspect predictable aspects of a model before fetching any actual
 * objects. This also helps a client understand where to listen for particular types of objects and
 * comprehend the model's structure in general.
 * 
 * <p>
 * For a primitive type, the type is given by {@link #getType()}. For {@link TargetObject}s,
 * supported interfaces are given by {@link #getInterfaces()}. The types of children are determined
 * by matching on the keys (indices and names), the result being a subordinate
 * {@link TargetObjectSchema}. Keys must match exactly, unless the "pattern" is the empty string,
 * which matches any key. Similarly, the wild-card index is {@code []}.
 */
public interface TargetObjectSchema {
	/**
	 * An identifier for schemas within a context.
	 * 
	 * This is essentially a wrapper on {@link String}, but typed so that strings and names cannot
	 * be accidentally interchanged.
	 */
	class SchemaName implements Comparable<SchemaName> {
		private final String name;

		/**
		 * Create an identifier with the given name
		 * 
		 * <p>
		 * In most cases, this constructor should always be wrapped in a cache, e.g.,
		 * {@link Map#computeIfAbsent(Object, java.util.function.Function)}.
		 * 
		 * @param name the name
		 */
		public SchemaName(String name) {
			this.name = Objects.requireNonNull(name);
		}

		/**
		 * {@inheritDoc}
		 * 
		 * @return the name
		 */
		@Override
		public String toString() {
			return name;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof SchemaName)) {
				return false;
			}
			SchemaName that = (SchemaName) obj;
			if (!this.name.equals(that.name)) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			return name.hashCode();
		}

		@Override
		public int compareTo(SchemaName o) {
			return this.name.compareTo(o.name);
		}
	}

	/**
	 * Schema descriptor for a child attribute.
	 */
	interface AttributeSchema {
		/**
		 * A descriptor suitable as a default that imposes no restrictions.
		 */
		AttributeSchema DEFAULT_ANY = new DefaultAttributeSchema("",
			EnumerableTargetObjectSchema.ANY.getName(), false, false, true);
		/**
		 * A descriptor suitable as a default that requires an object
		 */
		AttributeSchema DEFAULT_OBJECT = new DefaultAttributeSchema("",
			EnumerableTargetObjectSchema.OBJECT.getName(), false, false, true);
		/**
		 * A descriptor suitable as a default that forbids an attribute name
		 */
		AttributeSchema DEFAULT_VOID = new DefaultAttributeSchema("",
			EnumerableTargetObjectSchema.VOID.getName(), false, true, true);

		/**
		 * Get the name of the attribute
		 * 
		 * @return the name of the attribute
		 */
		String getName();

		/**
		 * Get the schema name for the named attribute
		 * 
		 * @return the schema name
		 */
		SchemaName getSchema();

		/**
		 * Check if the named attribute must always be present
		 * 
		 * @return true if required, false if optional
		 */
		boolean isRequired();

		/**
		 * Check if the named attribute can be modified
		 * 
		 * @return true if immutable, false if mutable
		 */
		boolean isFixed();

		/**
		 * Check if the named attribute should be displayed be default
		 * 
		 * <p>
		 * This is purely a UI hint. It has no other semantic consequence.
		 * 
		 * @return true if hidden, false if visible
		 */
		boolean isHidden();
	}

	/**
	 * Get the context of which this schema is a member
	 * 
	 * <p>
	 * All schema names are resolved in this same context
	 * 
	 * @return the context
	 */
	SchemaContext getContext();

	/**
	 * Get the name of this schema
	 * 
	 * @return the name
	 */
	SchemaName getName();

	/**
	 * Get the Java class that best represents this type.
	 * 
	 * <p>
	 * Note that this is either a primitive, or {@link TargetObject}. Even though an object
	 * implementation is necessarily a sub-type of {@link TargetObject}, for any object schema, this
	 * return {@link TargetObject}. Information about a "sub-type" of object is communicated via
	 * interfaces, element schemas, and attribute schemas.
	 * 
	 * @return the Java class for this type
	 */
	Class<?> getType();

	/**
	 * Get the minimum interfaces supported by a conforming object
	 * 
	 * @return the set of required interfaces
	 */
	Set<Class<? extends TargetObject>> getInterfaces();

	/**
	 * Check if this object is the canonical container for its elements
	 * 
	 * <p>
	 * This is generally in reference to the default type of this object's elements. For example, if
	 * elements of this object are all expected to support the "Process" interface, then this is the
	 * canonical Process container. Any Process ought to have a (canonical) path in this container.
	 * Any other path referring to such a Process ought to be a link.
	 * 
	 * <p>
	 * NOTE: the concept of links is still in incubation, as some native debugging APIs seem to have
	 * made it difficult to detect object identity. Additionally, it's possible a caller's first
	 * encounter with an object is not via its canonical path, and it may be difficult to assign a
	 * path having only the native-API-given object in hand.
	 * 
	 * @return true if this is a canonical container, false otherwise
	 */
	boolean isCanonicalContainer();

	/**
	 * Get the map of element indices to named schemas
	 * 
	 * <p>
	 * It is uncommon for this map to be populated, since the elements of a given container are
	 * typically uniform in type. Nevertheless, there can be restrictions imposed on -- and
	 * information provided for -- specific indices.
	 * 
	 * @return the map
	 */
	Map<String, SchemaName> getElementSchemas();

	/**
	 * Get the default schema for elements
	 * 
	 * <p>
	 * Since elements of a given container are typically uniform in type, this is the primary means
	 * of specifying element schemas.
	 * 
	 * @return the default named schema
	 */
	default SchemaName getDefaultElementSchema() {
		return EnumerableTargetObjectSchema.OBJECT.getName();
	}

	/**
	 * Get the named schema for a given element index
	 * 
	 * <p>
	 * If there's a schema specified for the given index, that schema is taken. Otherwise, the
	 * default element schema is taken.
	 * 
	 * @param index the index
	 * @return the named schema
	 */
	default SchemaName getElementSchema(String index) {
		for (Entry<String, SchemaName> ent : getElementSchemas().entrySet()) {
			if (ent.getKey().equals(index)) {
				return ent.getValue();
			}
		}
		return getDefaultElementSchema();
	}

	/**
	 * Get the map of attribute names to named schemas
	 * 
	 * @return the map
	 */
	Map<String, AttributeSchema> getAttributeSchemas();

	/**
	 * Get the default schema for attributes
	 * 
	 * <p>
	 * Since the expected attributes and their respective schemas are generally enumerated, this
	 * most commonly returns {@link AttributeSchema#DEFAULT_ANY}, to allow unrestricted use of
	 * additional attributes, or {@link AttributeSchema#DEFAULT_VOID}, to forbid any additional
	 * attributes.
	 * 
	 * @return the default attribute schema
	 */
	default AttributeSchema getDefaultAttributeSchema() {
		return AttributeSchema.DEFAULT_ANY;
	}

	/**
	 * Get the attribute schema for a given attribute name
	 * 
	 * <p>
	 * If there's a schema specified for the given name, that schema is taken. Otherwise, the
	 * default attribute schema is taken.
	 * 
	 * @param name the name
	 * @return the attribute schema
	 */
	default AttributeSchema getAttributeSchema(String name) {
		for (Entry<String, AttributeSchema> ent : getAttributeSchemas().entrySet()) {
			if (ent.getKey().equals(name)) {
				return ent.getValue();
			}
		}
		return getDefaultAttributeSchema();
	}

	/**
	 * Get the named schema for a child having the given key
	 * 
	 * @param key the key
	 * @return the named schema
	 */
	default SchemaName getChildSchemaName(String key) {
		if (PathUtils.isIndex(key)) {
			return getElementSchema(PathUtils.parseIndex(key));
		}
		return getAttributeSchema(key).getSchema();
	}

	/**
	 * Get the schema for a child having the given key
	 * 
	 * <p>
	 * This is the preferred method for navigating a schema and computing the expected type of a
	 * child.
	 * 
	 * @param key the key
	 * @return the schema
	 */
	default TargetObjectSchema getChildSchema(String key) {
		SchemaName name = getChildSchemaName(key);
		return getContext().getSchema(name);
	}

	/**
	 * Get the schema for a successor at the given (sub) path
	 * 
	 * <p>
	 * If this is the schema of the root object, then this gives the schema of the object at the
	 * given path in the model.
	 * 
	 * @param path the relative path from an object having this schema to the desired successor
	 * @return the schema for the successor
	 */
	default TargetObjectSchema getSuccessorSchema(List<String> path) {
		if (path.isEmpty()) {
			return this;
		}
		TargetObjectSchema childSchema = getChildSchema(path.get(0));
		return childSchema.getSuccessorSchema(path.subList(1, path.size()));
	}

	/**
	 * Find (sub) path patterns that match objects implementing a given interface
	 * 
	 * <p>
	 * Each returned path pattern accepts relative paths from an object having this schema to a
	 * successor implementing the interface.
	 * 
	 * @param type the sub-type of {@link TargetObject} to search for
	 * @param requireCanonical only return patterns matching a canonical location for the type
	 * @return a set of patterns where such objects could be found
	 */
	default Set<PathPattern> searchFor(Class<? extends TargetObject> type,
			boolean requireCanonical) {
		if (type == TargetObject.class) {
			throw new IllegalArgumentException("Must provide a specific interface");
		}
		Set<PathPattern> result = new LinkedHashSet<>();
		searchFor(result, List.of(), false, type, requireCanonical);
		return result;
	}

	@Internal // TODO: Make a separate internal interface?
	default void searchFor(Set<PathPattern> result, List<String> prefix, boolean parentIsCanonical,
			Class<? extends TargetObject> type, boolean requireCanonical) {
		if (getInterfaces().contains(type) && parentIsCanonical) {
			result.add(new PathPattern(prefix));
		}

		for (Entry<String, SchemaName> ent : getElementSchemas().entrySet()) {
			List<String> extended = PathUtils.index(prefix, ent.getKey());
			TargetObjectSchema elemSchema = getContext().getSchema(ent.getValue());
			elemSchema.searchFor(result, extended, isCanonicalContainer(), type, requireCanonical);
		}
		List<String> deExtended = PathUtils.extend(prefix, "[]");
		TargetObjectSchema deSchema = getContext().getSchema(getDefaultElementSchema());
		deSchema.searchFor(result, deExtended, isCanonicalContainer(), type, requireCanonical);

		for (Entry<String, AttributeSchema> ent : getAttributeSchemas().entrySet()) {
			List<String> extended = PathUtils.extend(prefix, ent.getKey());
			TargetObjectSchema attrSchema = getContext().getSchema(ent.getValue().getSchema());
			attrSchema.searchFor(result, extended, isCanonicalContainer(), type, requireCanonical);
		}
		List<String> daExtended = PathUtils.extend(prefix, "");
		TargetObjectSchema daSchema =
			getContext().getSchema(getDefaultAttributeSchema().getSchema());
		daSchema.searchFor(result, daExtended, isCanonicalContainer(), type, requireCanonical);
	}

	/**
	 * Check if the given key should be hidden for an object having this schema
	 * 
	 * <p>
	 * Elements ought never to be hidden. Otherwise, this defers to the attribute schema. As a
	 * special case, if the attribute schema is {@link AttributeSchema#DEFAULT_ANY} or
	 * {@link AttributeSchema#DEFAULT_OBJECT}, then it checks if the attribute starts with
	 * {@link TargetObject#PREFIX_INVISIBLE}. That convention is deprecated, and no new code should
	 * rely on that prefix. The special case provides a transition point for client-side code that
	 * would like to use the schema's definition for controlling visibility, but still support
	 * models which have not implemented schemas.
	 * 
	 * @param key the child key to check
	 * @return true if hidden
	 */
	default boolean isHidden(String key) {
		if (PathUtils.isIndex(key)) {
			return false;
		}
		AttributeSchema schema = getAttributeSchema(key);
		if (schema == AttributeSchema.DEFAULT_ANY || schema == AttributeSchema.DEFAULT_OBJECT) {
			// FIXME: Remove this hack once we stop depending on this prefix
			return key.startsWith(TargetObject.PREFIX_INVISIBLE);
		}
		return schema.isHidden();
	}

	/**
	 * Verify that the given value is of this schema's required type and, if applicable, implements
	 * the required interfaces
	 * 
	 * @param value the value
	 */
	default void validateTypeAndInterfaces(Object value, String key, boolean strict) {
		Class<?> cls = value.getClass();
		if (!getType().isAssignableFrom(cls)) {
			String msg = key == null
					? "Value " + value + " does not conform to required type " +
						getType() + " of schema " + this
					: "Value " + value + " for " + key + " does not conform to required type " +
						getType() + " of schema " + this;
			if (strict) {
				throw new AssertionError(msg);
			}
			Msg.error(this, msg);
		}
		for (Class<? extends TargetObject> iface : getInterfaces()) {
			if (!iface.isAssignableFrom(cls)) {
				// TODO: Should this throw an exception, eventually?
				String msg = "Value " + value + " does not implement required interface " +
					iface + " of schema " + this;
				if (strict) {
					throw new AssertionError(msg);
				}
				Msg.error(this, msg);
			}
		}
	}

	/**
	 * Verify that all required attributes are present
	 * 
	 * <p>
	 * Note: this should be called not at construction, but when the object is actually added to the
	 * model, e.g., when it appears in the "added" set of
	 * {@link DefaultTargetObject#setAttributes(Map, String)} called on its parent.
	 */
	default void validateRequiredAttributes(TargetObject object, boolean strict) {
		Set<String> present = object.getCachedAttributes().keySet();
		Set<String> missing = getAttributeSchemas()
				.values()
				.stream()
				.filter(AttributeSchema::isRequired)
				.map(AttributeSchema::getName)
				.filter(a -> !present.contains(a))
				.collect(Collectors.toSet());
		if (!missing.isEmpty()) {
			String msg = "Object " + object + " is missing required attributes " + missing +
				" of schema " + this;
			if (strict) {
				throw new AssertionError(msg);
			}
			Msg.error(this, msg);
		}
	}

	/**
	 * Verify that the given change does not cause a violation of the attribute schema
	 * 
	 * <p>
	 * For attributes, there are multiple possibilities of violation:
	 * </p>
	 * 
	 * <ul>
	 * <li>The type of an added attribute does not conform</li>
	 * <li>A required attribute is removed</li>
	 * <li>A fixed attribute is changed</li>
	 * </ul>
	 * 
	 * @param delta the delta, before or after the fact
	 */
	default void validateAttributeDelta(TargetObject object, Delta<?, ?> delta, boolean strict) {
		for (Map.Entry<String, ?> ent : delta.added.entrySet()) {
			String key = ent.getKey();
			Object value = ent.getValue();
			AttributeSchema as = getAttributeSchema(key);
			TargetObjectSchema schema = getContext().getSchema(as.getSchema());
			/**
			 * TODO: There's some duplication of effort here, since canonical attributes will
			 * already have been checked at construction.
			 */
			schema.validateTypeAndInterfaces(value, key, strict);

			if (value instanceof TargetObject) {
				TargetObject ov = (TargetObject) value;
				if (!PathUtils.isLink(object.getPath(), ent.getKey(), ov.getPath())) {
					schema.validateRequiredAttributes(ov, strict);
				}
			}
		}

		// TODO: Creating these sets *every* change could be costly
		// NB. "keysRemoved" does not include changed things, just removed
		Set<String> violatesRequired = getAttributeSchemas().values()
				.stream()
				.filter(AttributeSchema::isRequired)
				.map(AttributeSchema::getName)
				.filter(delta.getKeysRemoved()::contains)
				.collect(Collectors.toSet());
		if (!violatesRequired.isEmpty()) {
			String msg = "Object " + object + " removed required attributes " +
				violatesRequired + " of schema " + this;
			if (strict) {
				throw new AssertionError(msg);
			}
			Msg.error(this, msg);
		}
		// TODO: Another set....
		// NB. "removed" includes changed things
		// NB. I don't care about "new" attributes, since those don't violate "fixed"
		// TODO: Should "new, fixed" attributes be allowed after the object enters the model
		Set<String> violatesFixed = getAttributeSchemas().values()
				.stream()
				.filter(AttributeSchema::isFixed)
				.map(AttributeSchema::getName)
				.filter(delta.removed::containsKey)
				.collect(Collectors.toSet());
		if (!violatesFixed.isEmpty()) {
			if (strict) {

			}
			String msg = "Object " + object + " modified or removed fixed attributes " +
				violatesFixed + " of schema " + this;
			if (strict) {
				throw new AssertionError(msg);
			}
			Msg.error(this, msg);
		}
	}

	/**
	 * Verify that the given change does not cause a violation of the element schema
	 * 
	 * <p>
	 * For elements, we can only check whether the type conforms. Important within that, however, is
	 * that we verify the elements all have their required attributes.
	 * 
	 * @param delta the delta, before or after the fact
	 */
	default void validateElementDelta(TargetObject object, Delta<?, ? extends TargetObject> delta,
			boolean strict) {
		for (Map.Entry<String, ? extends TargetObject> ent : delta.added.entrySet()) {
			TargetObjectSchema schema = getContext().getSchema(getElementSchema(ent.getKey()));
			schema.validateRequiredAttributes(ent.getValue(), strict);
		}
	}
}
