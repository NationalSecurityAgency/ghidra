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
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetAggregate;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.DefaultTargetObjectSchema.DefaultAttributeSchema;
import ghidra.dbg.util.*;
import ghidra.dbg.util.CollectionUtils.Delta;
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
	public static final ResyncMode DEFAULT_ELEMENT_RESYNC = ResyncMode.NEVER;
	public static final ResyncMode DEFAULT_ATTRIBUTE_RESYNC = ResyncMode.NEVER;

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
	 * A mode describing what "promise" a model makes when keeping elements or attributes up to date
	 * 
	 * <p>
	 * Each object specifies a element sync mode, and an attribute sync mode. These describe when
	 * the client must call {@link TargetObject#resync(boolean, boolean)} to refresh/resync to
	 * ensure it has a fresh cache of elements and/or attributes. Note that any client requesting a
	 * resync will cause all clients to receive the updates.
	 */
	enum ResyncMode {
		/**
		 * The object's elements are kept up to date via unsolicited push notifications / callbacks
		 * 
		 * <p>
		 * The client should never have to call {@link TargetObject#resync()}. This is the default,
		 * and it is preferred for attributes. It is most appropriate for small-ish collections that
		 * change often and that the client is likely to need, e.g., the process, thread, and module
		 * lists. In general, if the native debugger or API offers callbacks for updating the
		 * collection, then this is the mode to use.
		 */
		NEVER {
			@Override
			public boolean shouldResync(CompletableFuture<Void> curRequest) {
				return false;
			}
		},
		/**
		 * The object must be explicitly synchronized once
		 * 
		 * <p>
		 * This mode is appropriate for large collections, e.g., the symbols of a module. To push
		 * these without solicitation could be expensive, both for the model to retrieve them from
		 * the debugger, and for the client to process the collection. They should only be retrieved
		 * when asked, via {@link TargetObject#resync()}. Such collections are typically fixed, and
		 * so do not require later updates. Nevertheless, if the collection <em>does</em> change,
		 * then those updates must be pushed without further solicitation.
		 */
		ONCE {
			@Override
			public boolean shouldResync(CompletableFuture<Void> curRequest) {
				return curRequest == null || curRequest.isCompletedExceptionally();
			}
		},
		/**
		 * The object's elements are only updated when requested
		 * 
		 * <p>
		 * This is the default for elements. It is appropriate for collections where the client
		 * doesn't necessarily need an up-to-date copy. Please note the higher likelihood that the
		 * client may make requests involving an object that has since become invalid. The model
		 * must be prepared to reject those requests gracefully. The most common example is the list
		 * of attachable processes: It should only be retrieved when requested, and there's no need
		 * to keep it up to date. If a process terminates, and the client later requests to attach
		 * to it, the request may be rejected.
		 */
		ALWAYS {
			@Override
			public boolean shouldResync(CompletableFuture<Void> curRequest) {
				return true;
			}
		};

		public abstract boolean shouldResync(CompletableFuture<Void> curRequest);
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
	 * Get the re-synchronization mode for the object's elements
	 * 
	 * @return the element re-synchronization mode
	 */
	ResyncMode getElementResyncMode();

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
	 * Get the re-synchronization mode for attributes
	 * 
	 * @return the attribute re-synchronization mode
	 */
	ResyncMode getAttributeResyncMode();

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
	 * Do the same as {@link #searchFor(Class, List, boolean)} with an empty prefix
	 */
	default PathMatcher searchFor(Class<? extends TargetObject> type, boolean requireCanonical) {
		return searchFor(type, List.of(), requireCanonical);
	}

	/**
	 * Find (sub) path patterns that match objects implementing a given interface
	 * 
	 * <p>
	 * Each returned path pattern accepts relative paths from an object having this schema to a
	 * successor implementing the interface.
	 * 
	 * @param type the sub-type of {@link TargetObject} to search for
	 * @param prefix the prefix for each relative path pattern
	 * @param requireCanonical only return patterns matching a canonical location for the type
	 * @return a set of patterns where such objects could be found
	 */
	default PathMatcher searchFor(Class<? extends TargetObject> type, List<String> prefix,
			boolean requireCanonical) {
		if (type == TargetObject.class) {
			throw new IllegalArgumentException("Must provide a specific interface");
		}
		PathMatcher result = new PathMatcher();
		Private.searchFor(this, result, prefix, true, type, requireCanonical, new HashSet<>());
		return result;
	}

	class Private {
		private abstract static class BreadthFirst<T extends SearchEntry> {
			Set<T> allOnLevel = new HashSet<>();

			public BreadthFirst(Set<T> seed) {
				allOnLevel.addAll(seed);
			}

			public void expandAttributes(Set<T> nextLevel, T ent) {
				SchemaContext ctx = ent.schema.getContext();
				for (AttributeSchema as : ent.schema.getAttributeSchemas().values()) {
					try {
						SchemaName schema = as.getSchema();
						TargetObjectSchema child = ctx.getSchema(schema);
						expandAttribute(nextLevel, ent, child,
							PathUtils.extend(ent.path, as.getName()));
					}
					catch (NullPointerException npe) {
						Msg.error(this, "Null schema for " + as);
					}
				}
			}

			public void expandDefaultAttribute(Set<T> nextLevel, T ent) {
				SchemaContext ctx = ent.schema.getContext();
				AttributeSchema das = ent.schema.getDefaultAttributeSchema();
				TargetObjectSchema child = ctx.getSchema(das.getSchema());
				expandAttribute(nextLevel, ent, child, PathUtils.extend(ent.path, das.getName()));
			}

			public void expandElements(Set<T> nextLevel, T ent) {
				SchemaContext ctx = ent.schema.getContext();
				for (Map.Entry<String, SchemaName> elemEnt : ent.schema.getElementSchemas()
						.entrySet()) {
					TargetObjectSchema child = ctx.getSchema(elemEnt.getValue());
					expandElement(nextLevel, ent, child,
						PathUtils.index(ent.path, elemEnt.getKey()));
				}
			}

			public void expandDefaultElement(Set<T> nextLevel, T ent) {
				SchemaContext ctx = ent.schema.getContext();
				TargetObjectSchema child = ctx.getSchema(ent.schema.getDefaultElementSchema());
				expandElement(nextLevel, ent, child, PathUtils.index(ent.path, ""));
			}

			public void nextLevel() {
				Set<T> nextLevel = new HashSet<>();
				for (T ent : allOnLevel) {
					if (!descend(ent)) {
						continue;
					}
					expandAttributes(nextLevel, ent);
					expandDefaultAttribute(nextLevel, ent);
					expandElements(nextLevel, ent);
					expandDefaultElement(nextLevel, ent);
				}
				allOnLevel = nextLevel;
			}

			public boolean descend(T ent) {
				return true;
			}

			public void expandAttribute(Set<T> nextLevel, T ent, TargetObjectSchema schema,
					List<String> path) {
			}

			public void expandElement(Set<T> nextLevel, T ent, TargetObjectSchema schema,
					List<String> path) {
			}
		}

		private static class SearchEntry {
			final List<String> path;
			final TargetObjectSchema schema;

			public SearchEntry(List<String> path, TargetObjectSchema schema) {
				this.path = path;
				this.schema = schema;
			}
		}

		private static class CanonicalSearchEntry extends SearchEntry {
			final boolean parentIsCanonical;

			public CanonicalSearchEntry(List<String> path, boolean parentIsCanonical,
					TargetObjectSchema schema) {
				super(path, schema);
				this.parentIsCanonical = parentIsCanonical;
			}
		}

		private static void searchFor(TargetObjectSchema sch, PathMatcher result,
				List<String> prefix, boolean parentIsCanonical, Class<? extends TargetObject> type,
				boolean requireCanonical, Set<TargetObjectSchema> visited) {
			if (!visited.add(sch)) {
				return;
			}

			if (sch.getInterfaces().contains(type) && parentIsCanonical) {
				result.addPattern(prefix);
			}
			SchemaContext ctx = sch.getContext();
			boolean isCanonical = sch.isCanonicalContainer();
			for (Entry<String, SchemaName> ent : sch.getElementSchemas().entrySet()) {
				List<String> extended = PathUtils.index(prefix, ent.getKey());
				TargetObjectSchema elemSchema = ctx.getSchema(ent.getValue());
				searchFor(elemSchema, result, extended, isCanonical, type, requireCanonical,
					visited);
			}
			List<String> deExtended = PathUtils.extend(prefix, "[]");
			TargetObjectSchema deSchema = ctx.getSchema(sch.getDefaultElementSchema());
			searchFor(deSchema, result, deExtended, isCanonical, type, requireCanonical, visited);

			for (Entry<String, AttributeSchema> ent : sch.getAttributeSchemas().entrySet()) {
				List<String> extended = PathUtils.extend(prefix, ent.getKey());
				TargetObjectSchema attrSchema = ctx.getSchema(ent.getValue().getSchema());
				searchFor(attrSchema, result, extended, parentIsCanonical, type, requireCanonical,
					visited);
			}
			List<String> daExtended = PathUtils.extend(prefix, "");
			TargetObjectSchema daSchema =
				ctx.getSchema(sch.getDefaultAttributeSchema().getSchema());
			searchFor(daSchema, result, daExtended, parentIsCanonical, type, requireCanonical,
				visited);

			visited.remove(sch);
		}

		static List<String> searchForSuitableInAggregate(TargetObjectSchema seed,
				Class<? extends TargetObject> type) {
			Set<SearchEntry> init = Set.of(new SearchEntry(List.of(), seed));
			BreadthFirst<SearchEntry> breadth = new BreadthFirst<>(init) {
				final Set<TargetObjectSchema> visited = new HashSet<>();

				@Override
				public boolean descend(SearchEntry ent) {
					return ent.schema.getInterfaces().contains(TargetAggregate.class);
				}

				@Override
				public void expandAttribute(Set<SearchEntry> nextLevel, SearchEntry ent,
						TargetObjectSchema schema, List<String> path) {
					if (visited.add(schema)) {
						nextLevel.add(new SearchEntry(path, schema));
					}
				}

				@Override
				public void expandDefaultAttribute(Set<SearchEntry> nextLevel, SearchEntry ent) {
				}

				@Override
				public void expandElements(Set<SearchEntry> nextLevel, SearchEntry ent) {
				}

				@Override
				public void expandDefaultElement(Set<SearchEntry> nextLevel, SearchEntry ent) {
				}
			};
			while (!breadth.allOnLevel.isEmpty()) {
				Set<SearchEntry> found = breadth.allOnLevel.stream()
						.filter(ent -> ent.schema.getInterfaces().contains(type))
						.collect(Collectors.toSet());
				if (!found.isEmpty()) {
					if (found.size() == 1) {
						return found.iterator().next().path;
					}
					return null;
				}
				breadth.nextLevel();
			}
			return null;
		}
	}

	/**
	 * Find the (sub) path to the canonical container for objects implementing a given interface
	 * 
	 * <p>
	 * If more than one container is found having the shortest path, then {@code null} is returned.
	 * 
	 * @param type the sub-type of {@link TargetObject} to search for
	 * @return the single path to that container
	 */
	default List<String> searchForCanonicalContainer(Class<? extends TargetObject> type) {
		if (type == TargetObject.class) {
			throw new IllegalArgumentException("Must provide a specific interface");
		}
		SchemaContext ctx = getContext();
		Set<TargetObjectSchema> visited = new HashSet<>();
		Set<TargetObjectSchema> visitedAsElement = new HashSet<>();
		Set<Private.CanonicalSearchEntry> allOnLevel = new HashSet<>();
		allOnLevel.add(new Private.CanonicalSearchEntry(List.of(), false, this));
		while (!allOnLevel.isEmpty()) {
			List<String> found = null;
			for (Private.CanonicalSearchEntry ent : allOnLevel) {
				if (ent.schema.getInterfaces().contains(type) && ent.parentIsCanonical) {
					// Check for final being index is in parentIsCanonical.
					if (found != null) {
						return null; // Non-unique answer
					}
					found = PathUtils.parent(ent.path);
				}
			}
			if (found != null) {
				return List.copyOf(found); // Unique shortest answer
			}

			Set<Private.CanonicalSearchEntry> nextLevel = new HashSet<>();
			for (Private.CanonicalSearchEntry ent : allOnLevel) {
				if (PathPattern.isWildcard(PathUtils.getKey(ent.path))) {
					continue;
				}
				for (Map.Entry<String, AttributeSchema> attrEnt : ent.schema.getAttributeSchemas()
						.entrySet()) {
					TargetObjectSchema attrSchema = ctx.getSchema(attrEnt.getValue().getSchema());
					if (TargetObject.class.isAssignableFrom(attrSchema.getType()) &&
						visited.add(attrSchema)) {
						nextLevel.add(new Private.CanonicalSearchEntry(
							PathUtils.extend(ent.path, attrEnt.getKey()), false, // If child is not element, this is not is canonical container
							attrSchema));
					}
				}
				for (Map.Entry<String, SchemaName> elemEnt : ent.schema.getElementSchemas()
						.entrySet()) {
					TargetObjectSchema elemSchema = ctx.getSchema(elemEnt.getValue());
					visited.add(elemSchema); // Add but do not condition
					if (visitedAsElement.add(elemSchema)) {
						nextLevel.add(new Private.CanonicalSearchEntry(
							PathUtils.index(ent.path, elemEnt.getKey()),
							ent.schema.isCanonicalContainer(), elemSchema));
					}
				}
				TargetObjectSchema deSchema = ctx.getSchema(ent.schema.getDefaultElementSchema());
				visited.add(deSchema);
				if (visitedAsElement.add(deSchema)) {
					nextLevel.add(new Private.CanonicalSearchEntry(PathUtils.index(ent.path, ""),
						ent.schema.isCanonicalContainer(), deSchema));
				}
			}
			allOnLevel = nextLevel;
		}
		// We exhausted the reachable schemas
		return null;
	}

	default List<String> searchForSuitable(Class<? extends TargetObject> type, List<String> path) {
		for (; path != null; path = PathUtils.parent(path)) {
			TargetObjectSchema schema = getSuccessorSchema(path);
			if (schema.getInterfaces().contains(type)) {
				return path;
			}
			List<String> inAgg = Private.searchForSuitableInAggregate(schema, type);
			if (inAgg != null) {
				return PathUtils.extend(path, inAgg);
			}
		}
		return null;
	}

	default List<String> searchForAncestor(Class<? extends TargetObject> type, List<String> path) {
		for (; path != null; path = PathUtils.parent(path)) {
			TargetObjectSchema schema = getSuccessorSchema(path);
			if (schema.getInterfaces().contains(type)) {
				return path;
			}
		}
		return null;
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
	default void validateTypeAndInterfaces(Object value, List<String> parentPath, String key,
			boolean strict) {
		Class<?> cls = value.getClass();
		if (!getType().isAssignableFrom(cls)) {
			String path =
				key == null ? null : PathUtils.toString(PathUtils.extend(parentPath, key));
			String msg = path == null
					? "Value " + value + " does not conform to required type " + getType() +
						" of schema " + this
					: "Value " + value + " for " + path + " does not conform to required type " +
						getType() + " of schema " + this;
			Msg.error(this, msg);
			if (strict) {
				throw new AssertionError(msg);
			}
		}
		for (Class<? extends TargetObject> iface : getInterfaces()) {
			if (!iface.isAssignableFrom(cls)) {
				// TODO: Should this throw an exception, eventually?
				String msg = "Value " + value + " does not implement required interface " + iface +
					" of schema " + this;
				Msg.error(this, msg);
				if (strict) {
					throw new AssertionError(msg);
				}
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
		Set<String> missing = getAttributeSchemas().values()
				.stream()
				.filter(AttributeSchema::isRequired)
				.map(AttributeSchema::getName)
				.filter(a -> !present.contains(a))
				.collect(Collectors.toSet());
		if (!missing.isEmpty()) {
			String msg = "Object " + object + " is missing required attributes " + missing +
				" of schema " + this;
			Msg.error(this, msg);
			if (strict) {
				throw new AssertionError(msg);
			}
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
	default void validateAttributeDelta(List<String> parentPath, Delta<?, ?> delta,
			boolean strict) {
		for (Map.Entry<String, ?> ent : delta.added.entrySet()) {
			String key = ent.getKey();
			Object value = ent.getValue();
			AttributeSchema as = getAttributeSchema(key);
			TargetObjectSchema schema = getContext().getSchema(as.getSchema());
			schema.validateTypeAndInterfaces(value, parentPath, key, strict);
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
			String msg = "Object " + parentPath + " removed required attributes " +
				violatesRequired + " of schema " + this;
			Msg.error(this, msg);
			if (strict) {
				throw new AssertionError(msg);
			}
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
			String msg = "Object " + parentPath + " modified or removed fixed attributes " +
				violatesFixed + " of schema " + this;
			Msg.error(this, msg);
			if (strict) {
				throw new AssertionError(msg);
			}
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
	default void validateElementDelta(List<String> parentPath,
			Delta<?, ? extends TargetObject> delta, boolean strict) {
		for (Map.Entry<String, ? extends TargetObject> ent : delta.added.entrySet()) {
			TargetObject element = ent.getValue();
			TargetObjectSchema schema = getContext().getSchema(getElementSchema(ent.getKey()));
			schema.validateTypeAndInterfaces(element, parentPath, ent.getKey(), strict);
		}
	}
}
