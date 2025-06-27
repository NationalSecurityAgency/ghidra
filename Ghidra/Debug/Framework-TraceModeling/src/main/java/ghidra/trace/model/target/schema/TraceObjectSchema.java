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
import java.util.Map.Entry;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceRegisterContainer;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.iface.TraceAggregate;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.path.*;
import ghidra.trace.model.target.schema.DefaultTraceObjectSchema.DefaultAttributeSchema;
import ghidra.util.Msg;

/**
 * Type information for a particular value or {@link TraceObject}
 * 
 * <p>
 * This allows a client to inspect predictable aspects of a model before fetching any actual
 * objects. This also helps a client understand where to listen for particular types of objects and
 * comprehend the model's structure in general.
 * 
 * <p>
 * For a primitive type, the type is given by {@link #getType()}. For {@link TraceObject}s,
 * supported interfaces are given by {@link #getInterfaces()}. The types of children are determined
 * by matching on the keys (indices and names), the result being a subordinate
 * {@link TraceObjectSchema}. Keys must match exactly, unless the "pattern" is the empty string,
 * which matches any key. Similarly, the wild-card index is {@code []}.
 * 
 * <p>
 * The schema can specify attribute aliases, which implies that a particular key ("from") will
 * always have the same value as another ("to"). As a result, the schemas of aliased keys will also
 * implicitly match.
 */
public interface TraceObjectSchema {

	/**
	 * An identifier for schemas within a context.
	 *
	 * <p>
	 * This is essentially a wrapper on {@link String}, but typed so that strings and names cannot
	 * be accidentally interchanged.
	 * 
	 * <p>
	 * TODO: In retrospect, I'm not sure having this has improved anything. Might just replace this
	 * with a plain {@link String}.
	 * 
	 * @param name the name
	 */
	record SchemaName(String name) implements Comparable<SchemaName> {
		@Override
		public final String toString() {
			return name;
		}

		@Override
		public int compareTo(SchemaName o) {
			return this.name.compareTo(o.name);
		}
	}

	enum Hidden {
		DEFAULT {
			@Override
			public boolean isHidden(String name) {
				return name.startsWith("_");
			}

			@Override
			public Hidden adjust(String name) {
				return name.isEmpty() ? this : FALSE;
			}
		},
		TRUE {
			@Override
			public boolean isHidden(String name) {
				return true;
			}
		},
		FALSE {
			@Override
			public boolean isHidden(String name) {
				return false;
			}
		};

		public abstract boolean isHidden(String name);

		public Hidden adjust(String name) {
			return this;
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
			PrimitiveTraceObjectSchema.ANY.getName(), false, false, Hidden.DEFAULT);
		/**
		 * A descriptor suitable as a default that requires an object
		 */
		AttributeSchema DEFAULT_OBJECT = new DefaultAttributeSchema("",
			PrimitiveTraceObjectSchema.OBJECT.getName(), false, false, Hidden.DEFAULT);
		/**
		 * A descriptor suitable as a default that forbids an attribute name
		 */
		AttributeSchema DEFAULT_VOID = new DefaultAttributeSchema("",
			PrimitiveTraceObjectSchema.VOID.getName(), false, true, Hidden.TRUE);

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
		 * @param name the actual name of the attribute, in case this is the default attribute
		 * @return true if hidden, false if visible
		 */
		default boolean isHidden(String name) {
			return getHidden().isHidden(name);
		}

		Hidden getHidden();
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
	 * Note that this is either a primitive, or {@link TraceObject}. Even though an object
	 * implementation is necessarily a sub-type of {@link TraceObject}, for any object schema, this
	 * return {@link TraceObject}. Information about a "sub-type" of object is communicated via
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
	Set<Class<? extends TraceObjectInterface>> getInterfaces();

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
		return PrimitiveTraceObjectSchema.OBJECT.getName();
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
		SchemaName schemaName = getElementSchemas().get(index);
		return schemaName == null ? getDefaultElementSchema() : schemaName;
	}

	/**
	 * Get the map of attribute names to named schemas
	 * 
	 * <p>
	 * The returned map will include aliases. To determine whether or not an attribute key is an
	 * alias, check whether the entry's key matches the name of the attribute (see
	 * {@link AttributeSchema#getName()}). It is possible the schema's name is empty, i.e., the
	 * default schema. This indicates an alias to a key that was not named in the schema. Use
	 * {@link #getAttributeAliases()} to determine the name of that key.
	 * 
	 * @return the map
	 */
	Map<String, AttributeSchema> getAttributeSchemas();

	/**
	 * Get the map of attribute name aliases
	 * 
	 * <p>
	 * The returned map must provide the <em>direct</em> alias names. For any given key, the client
	 * need only query the map once to determine the name of the attribute to which the alias
	 * refers. Consequently, the map also cannot indicate a cycle.
	 * 
	 * <p>
	 * An aliased attribute takes the value of its target implicitly.
	 * 
	 * @return the map
	 */
	Map<String, String> getAttributeAliases();

	/**
	 * Check if the given name is an alias and get the target attribute name
	 * 
	 * @param name the name
	 * @return the alias' target, or the given name if not an alias
	 */
	default String checkAliasedAttribute(String name) {
		return getAttributeAliases().getOrDefault(name, name);
	}

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
	 * If there's a schema specified for the given name, that schema is taken. If the name refers to
	 * an alias, its schema is taken. Otherwise, the default attribute schema is taken.
	 * 
	 * @param name the name
	 * @return the attribute schema
	 */
	default AttributeSchema getAttributeSchema(String name) {
		AttributeSchema attributeSchema = getAttributeSchemas().get(name);
		return attributeSchema == null ? getDefaultAttributeSchema() : attributeSchema;
	}

	/**
	 * Get the named schema for a child having the given key
	 * 
	 * @param key the key
	 * @return the named schema
	 */
	default SchemaName getChildSchemaName(String key) {
		if (KeyPath.isIndex(key)) {
			return getElementSchema(KeyPath.parseIndex(key));
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
	default TraceObjectSchema getChildSchema(String key) {
		SchemaName name = getChildSchemaName(key);
		return getContext().getSchema(name);
	}

	/**
	 * Get the schema for a successor at the given (sub) path
	 * 
	 * <p>
	 * If this is the schema of the root object, then this gives the schema of the object at the
	 * given path in the model. This will always give a non-null result, though that result might be
	 * {@link PrimitiveTraceObjectSchema#VOID}.
	 * 
	 * @param path the relative path from an object having this schema to the desired successor
	 * @return the schema for the successor
	 */
	default TraceObjectSchema getSuccessorSchema(KeyPath path) {
		return Private.getSuccessorSchema(this, path, 0);
	}

	/**
	 * Get the list of schemas traversed from this schema along the given (sub) path
	 * 
	 * <p>
	 * This list always begins with this schema, followed by the child schema for each key in the
	 * path. Thus, for a path of length n, the resulting list has n+1 entries. This is useful for
	 * searches along the ancestry of a given path:
	 * 
	 * <pre>
	 * List<TargetObjectSchema> schemas = getSuccessorSchemas(path);
	 * for (; path != null; path = PathUtils.parent(path)) {
	 * 	TargetObjectSchema schema = schemas.get(path.size());
	 * 	// ...
	 * }
	 * </pre>
	 * 
	 * <p>
	 * All entries are non-null, though they may be {@link PrimitiveTraceObjectSchema#VOID}.
	 * 
	 * @param path the relative path from an object having this schema to the desired successor
	 * @return the list of schemas traversed, ending with the successor's schema
	 */
	default List<TraceObjectSchema> getSuccessorSchemas(KeyPath path) {
		List<TraceObjectSchema> result = new ArrayList<>();
		TraceObjectSchema schema = this;
		result.add(schema);
		for (String key : path) {
			schema = schema.getChildSchema(key);
			result.add(schema);
		}
		return result;
	}

	/**
	 * Do the same as {@link #searchFor(Class, KeyPath, boolean)} with an empty prefix
	 * 
	 * @param type the sub-type of {@link TraceObjectInterface} to search for
	 * @param requireCanonical only return patterns matching a canonical location for the type
	 * @return a set of patterns where such objects could be found
	 */
	default PathFilter searchFor(Class<? extends TraceObjectInterface> type,
			boolean requireCanonical) {
		return searchFor(type, KeyPath.ROOT, requireCanonical);
	}

	/**
	 * Find (sub) path patterns that match objects implementing a given interface
	 * 
	 * <p>
	 * Each returned path pattern accepts relative paths from an object having this schema to a
	 * successor implementing the interface.
	 * 
	 * @param type the sub-type of {@link TraceObjectInterface} to search for
	 * @param prefix the prefix for each relative path pattern
	 * @param requireCanonical only return patterns matching a canonical location for the type
	 * @return a set of patterns where such objects could be found
	 */
	default PathFilter searchFor(Class<? extends TraceObjectInterface> type, KeyPath prefix,
			boolean requireCanonical) {
		if (type == TraceObjectInterface.class) {
			throw new IllegalArgumentException("Must provide a specific interface");
		}
		Set<PathPattern> patterns = new HashSet<>();
		Private.searchFor(this, patterns, prefix, true, type, false, requireCanonical,
			new HashSet<>());
		return PathMatcher.any(patterns.stream());
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
						TraceObjectSchema child = ctx.getSchema(schema);
						expandAttribute(nextLevel, ent, child, ent.path.key(as.getName()));
					}
					catch (NullPointerException npe) {
						Msg.error(this, "Null schema for " + as);
					}
				}
			}

			public void expandDefaultAttribute(Set<T> nextLevel, T ent) {
				SchemaContext ctx = ent.schema.getContext();
				AttributeSchema das = ent.schema.getDefaultAttributeSchema();
				TraceObjectSchema child = ctx.getSchema(das.getSchema());
				expandAttribute(nextLevel, ent, child, ent.path.key(das.getName()));
			}

			public void expandElements(Set<T> nextLevel, T ent) {
				SchemaContext ctx = ent.schema.getContext();
				for (Map.Entry<String, SchemaName> elemEnt : ent.schema.getElementSchemas()
						.entrySet()) {
					TraceObjectSchema child = ctx.getSchema(elemEnt.getValue());
					expandElement(nextLevel, ent, child, ent.path.index(elemEnt.getKey()));
				}
			}

			public void expandDefaultElement(Set<T> nextLevel, T ent) {
				SchemaContext ctx = ent.schema.getContext();
				TraceObjectSchema child = ctx.getSchema(ent.schema.getDefaultElementSchema());
				expandElement(nextLevel, ent, child, ent.path.index(""));
			}

			public void nextLevel() {
				Set<T> nextLevel = new HashSet<>();
				for (T ent : allOnLevel) {
					if (descendAttributes(ent)) {
						expandAttributes(nextLevel, ent);
						expandDefaultAttribute(nextLevel, ent);
					}
					if (descendElements(ent)) {
						expandElements(nextLevel, ent);
						expandDefaultElement(nextLevel, ent);
					}
				}
				allOnLevel = nextLevel;
			}

			public boolean descendAttributes(T ent) {
				return true;
			}

			public boolean descendElements(T ent) {
				return true;
			}

			public void expandAttribute(Set<T> nextLevel, T ent, TraceObjectSchema schema,
					KeyPath path) {
			}

			public void expandElement(Set<T> nextLevel, T ent, TraceObjectSchema schema,
					KeyPath path) {
			}
		}

		private static class SearchEntry {
			final KeyPath path;
			final TraceObjectSchema schema;

			public SearchEntry(KeyPath path, TraceObjectSchema schema) {
				this.path = path;
				this.schema = schema;
			}
		}

		private static class CanonicalSearchEntry extends SearchEntry {
			final boolean parentIsCanonical;

			public CanonicalSearchEntry(KeyPath path, boolean parentIsCanonical,
					TraceObjectSchema schema) {
				super(path, schema);
				this.parentIsCanonical = parentIsCanonical;
			}
		}

		private static class InAggregateSearch extends BreadthFirst<SearchEntry> {
			final Set<TraceObjectSchema> visited = new HashSet<>();

			public InAggregateSearch(TraceObjectSchema seed) {
				super(Set.of(new SearchEntry(KeyPath.ROOT, seed)));
			}

			@Override
			public boolean descendAttributes(SearchEntry ent) {
				return ent.schema.getInterfaces().contains(TraceAggregate.class);
			}

			@Override
			public boolean descendElements(SearchEntry ent) {
				return ent.schema.isCanonicalContainer();
			}

			@Override
			public void expandAttribute(Set<SearchEntry> nextLevel, SearchEntry ent,
					TraceObjectSchema schema, KeyPath path) {
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
		}

		private static void searchFor(TraceObjectSchema sch, Set<PathPattern> patterns,
				KeyPath prefix, boolean parentIsCanonical,
				Class<? extends TraceObjectInterface> type,
				boolean requireAggregate, boolean requireCanonical,
				Set<TraceObjectSchema> visited) {
			if (sch instanceof PrimitiveTraceObjectSchema) {
				return;
			}
			if (sch.getInterfaces().contains(type) && (parentIsCanonical || !requireCanonical)) {
				patterns.add(new PathPattern(prefix));
				return;
			}
			if (!visited.add(sch)) {
				return;
			}
			if (requireAggregate && !sch.getInterfaces().contains(TraceAggregate.class)) {
				return;
			}
			SchemaContext ctx = sch.getContext();
			boolean isCanonical = sch.isCanonicalContainer();
			for (Entry<String, SchemaName> ent : sch.getElementSchemas().entrySet()) {
				KeyPath extended = prefix.index(ent.getKey());
				TraceObjectSchema elemSchema = ctx.getSchema(ent.getValue());
				searchFor(elemSchema, patterns, extended, isCanonical, type, requireAggregate,
					requireCanonical, visited);
			}
			KeyPath deExtended = prefix.key("[]");
			TraceObjectSchema deSchema = ctx.getSchema(sch.getDefaultElementSchema());
			searchFor(deSchema, patterns, deExtended, isCanonical, type, requireAggregate,
				requireCanonical, visited);

			for (Entry<String, AttributeSchema> ent : sch.getAttributeSchemas().entrySet()) {
				KeyPath extended = prefix.key(ent.getKey());
				TraceObjectSchema attrSchema = ctx.getSchema(ent.getValue().getSchema());
				searchFor(attrSchema, patterns, extended, isCanonical, type, requireAggregate,
					requireCanonical, visited);
			}
			KeyPath daExtended = prefix.key("");
			TraceObjectSchema daSchema =
				ctx.getSchema(sch.getDefaultAttributeSchema().getSchema());
			searchFor(daSchema, patterns, daExtended, isCanonical, type, requireAggregate,
				requireCanonical, visited);

			visited.remove(sch);
		}

		static KeyPath searchForInAggregate(TraceObjectSchema seed,
				Predicate<SearchEntry> predicate) {
			InAggregateSearch inAgg = new InAggregateSearch(seed);
			while (!inAgg.allOnLevel.isEmpty()) {
				Set<SearchEntry> found = inAgg.allOnLevel.stream()
						.filter(predicate)
						.collect(Collectors.toSet());
				if (!found.isEmpty()) {
					if (found.size() == 1) {
						return found.iterator().next().path;
					}
					return null;
				}
				inAgg.nextLevel();
			}
			return null;
		}

		static KeyPath searchForSuitableInAggregate(TraceObjectSchema seed,
				Class<? extends TraceObjectInterface> type) {
			return searchForInAggregate(seed, ent -> ent.schema.getInterfaces().contains(type));
		}

		static KeyPath searchForSuitableInAggregate(TraceObjectSchema seed,
				TraceObjectSchema schema) {
			return searchForInAggregate(seed, ent -> ent.schema == schema);
		}

		static KeyPath searchForSuitableContainerInAggregate(TraceObjectSchema seed,
				Class<? extends TraceObjectInterface> type) {
			return searchForInAggregate(seed, ent -> {
				if (!ent.schema.isCanonicalContainer()) {
					return false;
				}
				TraceObjectSchema deSchema =
					ent.schema.getContext().getSchema(ent.schema.getDefaultElementSchema());
				return deSchema.getInterfaces().contains(type);
			});
		}

		static TraceObjectSchema getSuccessorSchema(TraceObjectSchema schema, KeyPath path,
				int i) {
			if (i >= path.size()) {
				return schema;
			}
			TraceObjectSchema childSchema = schema.getChildSchema(path.key(i));
			return getSuccessorSchema(childSchema, path, i + 1);
		}
	}

	/**
	 * Find the (sub) path to the canonical container for objects implementing a given interface
	 * 
	 * <p>
	 * If more than one container is found having the shortest path, then {@code null} is returned.
	 * 
	 * @param type the sub-type of {@link TraceObjectInterface} to search for
	 * @return the single path to that container
	 */
	default KeyPath searchForCanonicalContainer(Class<? extends TraceObjectInterface> type) {
		if (type == TraceObjectInterface.class) {
			throw new IllegalArgumentException("Must provide a specific interface");
		}
		SchemaContext ctx = getContext();
		Set<TraceObjectSchema> visited = new HashSet<>();
		Set<TraceObjectSchema> visitedAsElement = new HashSet<>();
		Set<Private.CanonicalSearchEntry> allOnLevel = new HashSet<>();
		allOnLevel.add(new Private.CanonicalSearchEntry(KeyPath.ROOT, false, this));
		while (!allOnLevel.isEmpty()) {
			KeyPath found = null;
			for (Private.CanonicalSearchEntry ent : allOnLevel) {
				if (ent.schema.getInterfaces().contains(type) && ent.parentIsCanonical) {
					// Check for final being index is in parentIsCanonical.
					if (found != null) {
						return null; // Non-unique answer
					}
					found = ent.path.parent();
				}
			}
			if (found != null) {
				return found; // Unique shortest answer
			}

			Set<Private.CanonicalSearchEntry> nextLevel = new HashSet<>();
			for (Private.CanonicalSearchEntry ent : allOnLevel) {
				if (PathPattern.isWildcard(ent.path.key())) {
					continue;
				}
				for (Map.Entry<String, AttributeSchema> attrEnt : ent.schema.getAttributeSchemas()
						.entrySet()) {
					TraceObjectSchema attrSchema = ctx.getSchema(attrEnt.getValue().getSchema());
					if ((TraceObjectInterface.class.isAssignableFrom(attrSchema.getType()) ||
						TraceObject.class.isAssignableFrom(attrSchema.getType())) &&
						visited.add(attrSchema)) {
						nextLevel.add(new Private.CanonicalSearchEntry(
							ent.path.key(attrEnt.getKey()),
							// If child is not element, this is not its canonical container
							false, attrSchema));
					}
				}
				for (Map.Entry<String, SchemaName> elemEnt : ent.schema.getElementSchemas()
						.entrySet()) {
					TraceObjectSchema elemSchema = ctx.getSchema(elemEnt.getValue());
					visited.add(elemSchema); // Add but do not condition
					if (visitedAsElement.add(elemSchema)) {
						nextLevel.add(new Private.CanonicalSearchEntry(
							ent.path.index(elemEnt.getKey()),
							ent.schema.isCanonicalContainer(), elemSchema));
					}
				}
				TraceObjectSchema deSchema = ctx.getSchema(ent.schema.getDefaultElementSchema());
				visited.add(deSchema);
				if (visitedAsElement.add(deSchema)) {
					nextLevel.add(new Private.CanonicalSearchEntry(ent.path.index(""),
						ent.schema.isCanonicalContainer(), deSchema));
				}
			}
			allOnLevel = nextLevel;
		}
		// We exhausted the reachable schemas
		return null;
	}

	/**
	 * Search for a suitable object with this schema at the given path
	 * 
	 * @param type the type of object sought
	 * @param path the path of a seed object
	 * @return the expected path of the suitable object, or null
	 */
	default KeyPath searchForSuitable(Class<? extends TraceObjectInterface> type, KeyPath path) {
		List<TraceObjectSchema> schemas = getSuccessorSchemas(path);
		for (; path != null; path = path.parent()) {
			TraceObjectSchema schema = schemas.get(path.size());
			if (schema.getInterfaces().contains(type)) {
				return path;
			}
			KeyPath inAgg = Private.searchForSuitableInAggregate(schema, type);
			if (inAgg != null) {
				return path.extend(inAgg);
			}
		}
		return null;
	}

	/**
	 * Search for a suitable object with this schema at the given path
	 * 
	 * @param schema the schema of object sought
	 * @param path the path of a seed object
	 * @return the expected path of the suitable object, or null
	 */
	default KeyPath searchForSuitable(TraceObjectSchema schema, KeyPath path) {
		List<TraceObjectSchema> schemas = getSuccessorSchemas(path);
		for (; path != null; path = path.parent()) {
			TraceObjectSchema check = schemas.get(path.size());
			if (check == schema) {
				return path;
			}
			KeyPath inAgg = Private.searchForSuitableInAggregate(check, schema);
			if (inAgg != null) {
				return path.extend(inAgg);
			}
		}
		return null;
	}

	/**
	 * Search for all suitable objects with this schema at the given path
	 * 
	 * <p>
	 * This behaves like {@link #searchForSuitable(Class, KeyPath)}, except that it returns a
	 * matcher for all possibilities. Conventionally, when the client uses the matcher to find
	 * suitable objects and must choose from among the results, those having the longer paths should
	 * be preferred. More specifically, it should prefer those sharing the longer path prefixes with
	 * the given path. The client should <em>not</em> just take the first objects, since these will
	 * likely have the shortest paths. If exactly one object is required, consider using
	 * {@link #searchForSuitable(Class, KeyPath)} instead.
	 * 
	 * @param type
	 * @param path
	 * @return the filter for finding objects
	 */
	default PathFilter filterForSuitable(Class<? extends TraceObjectInterface> type, KeyPath path) {
		Set<PathPattern> patterns = new HashSet<>();
		Set<TraceObjectSchema> visited = new HashSet<>();
		List<TraceObjectSchema> schemas = getSuccessorSchemas(path);
		for (; path != null; path = path.parent()) {
			TraceObjectSchema schema = schemas.get(path.size());
			Private.searchFor(schema, patterns, path, false, type, true, false, visited);
		}
		return PathMatcher.any(patterns.stream());
	}

	/**
	 * Like {@link #searchForSuitable(Class, KeyPath)}, but searches for the canonical container
	 * whose elements have the given type
	 * 
	 * @param type the type of object sought
	 * @param path the path of a seed object
	 * @return the expected path of the suitable container of those objects, or null
	 */
	default KeyPath searchForSuitableContainer(Class<? extends TraceObjectInterface> type,
			KeyPath path) {
		List<TraceObjectSchema> schemas = getSuccessorSchemas(path);
		for (; path != null; path = path.parent()) {
			TraceObjectSchema schema = schemas.get(path.size());
			TraceObjectSchema deSchema =
				schema.getContext().getSchema(schema.getDefaultElementSchema());
			if (deSchema.getInterfaces().contains(type) && schema.isCanonicalContainer()) {
				return path;
			}
			KeyPath inAgg = Private.searchForSuitableContainerInAggregate(schema, type);
			if (inAgg != null) {
				return path.extend(inAgg);
			}
		}
		return null;
	}

	/**
	 * Find the nearest ancestor implementing the given interface along the given path
	 * 
	 * <p>
	 * If the given path implements the interface, it is returned, i.e., it is not strictly an
	 * ancestor.
	 * 
	 * @param type the interface to search for
	 * @param path the seed path
	 * @return the found path, or {@code null} if no ancestor implements the interface
	 */
	default KeyPath searchForAncestor(Class<? extends TraceObjectInterface> type, KeyPath path) {
		for (; path != null; path = path.parent()) {
			TraceObjectSchema schema = getSuccessorSchema(path);
			if (schema.getInterfaces().contains(type)) {
				return path;
			}
		}
		return null;
	}

	/**
	 * Find the nearest ancestor which is the canonical container of the given interface
	 * 
	 * <p>
	 * If the given path is such a container, it is returned, i.e., it is not strictly an ancestor.
	 * 
	 * @param type the interface whose canonical container to search for
	 * @param path the seed path
	 * @return the found path, or {@code null} if no such ancestor was found
	 */
	default KeyPath searchForAncestorContainer(Class<? extends TraceObjectInterface> type,
			KeyPath path) {
		for (; path != null; path = path.parent()) {
			TraceObjectSchema schema = getSuccessorSchema(path);
			if (!schema.isCanonicalContainer()) {
				continue;
			}
			TraceObjectSchema deSchema =
				schema.getContext().getSchema(schema.getDefaultElementSchema());
			if (deSchema.getInterfaces().contains(type)) {
				return path;
			}
		}
		return null;
	}

	/**
	 * Check if the given key should be hidden for an object having this schema
	 * 
	 * <p>
	 * Elements ought never to be hidden. Otherwise, this defers to the attribute schema.
	 * 
	 * @param key the child key to check
	 * @return true if hidden
	 */
	default boolean isHidden(String key) {
		if (KeyPath.isIndex(key)) {
			return false;
		}
		AttributeSchema schema = getAttributeSchema(key);
		return schema.isHidden(key);
	}

	/**
	 * Verify that the given value is of this schema's required type and, if applicable, implements
	 * the required interfaces
	 * 
	 * @param value the value being assigned to the key
	 * @param parentPath the path of the object whose key is being assigned, for diagnostics
	 * @param key the key that is being assigned
	 * @param strict true to throw an exception upon violation; false to just log and continue
	 */
	default void validateTypeAndInterfaces(Object value, KeyPath parentPath, String key,
			boolean strict) {
		Class<?> cls = value.getClass();
		if (!getType().isAssignableFrom(cls)) {
			String path = key == null ? null : parentPath.key(key).toString();
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
		for (Class<? extends TraceObjectInterface> iface : getInterfaces()) {
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
	 * NOTE: This may become part of a schema and/or connector tester/validator later.
	 * 
	 * @param object the object whose schema is this one
	 * @param strict to throw exceptions upon violations
	 * @param snap the relevant snapshot
	 */
	default void validateRequiredAttributes(TraceObject object, boolean strict, long snap) {
		Set<String> present = object.getAttributes(Lifespan.at(snap))
				.stream()
				.map(a -> a.getEntryKey())
				.collect(Collectors.toUnmodifiableSet());
		Set<String> absent = getAttributeSchemas().values()
				.stream()
				.filter(AttributeSchema::isRequired)
				.map(AttributeSchema::getName)
				.filter(a -> !present.contains(a))
				.collect(Collectors.toSet());
		if (!absent.isEmpty()) {
			String msg = "Object " + object + " is missing required attributes " + absent +
				" of schema " + this;
			Msg.error(this, msg);
			if (strict) {
				throw new AssertionError(msg);
			}
		}
	}

	/**
	 * Search for a suitable register container
	 * 
	 * <p>
	 * This will try with and without considerations for frames. If the schema indicates that
	 * register containers are not contained within frames, then frameLevel must be 0, otherwise
	 * this will return empty. If dependent on frameLevel, this will return two singleton paths: one
	 * for a decimal index and another for a hexadecimal index. If not, this will return a singleton
	 * path. If it fails to find a unique container, this will return empty.
	 * 
	 * <p>
	 * <b>NOTE:</b> This must be used at the top of the search scope, probably the root schema. For
	 * example, to search the entire model for a register container related to {@code myObject}:
	 * 
	 * <pre>
	 * for (PathPattern regPattern : myObject.getModel()
	 * 		.getSchema()
	 * 		.searchForRegisterContainer(0, myObject.getPath())) {
	 * 	TargetObject objRegs = myObject.getModel().getModelObject(regPattern.getSingletonPath());
	 * 	if (objRegs != null) {
	 * 		// found it
	 * 	}
	 * }
	 * </pre>
	 * 
	 * <p>
	 * This places some conventional restrictions / expectations on models where registers are given
	 * on a frame-by-frame basis. The schema should present the {@link TraceRegisterContainer}
	 * as the same object or a successor to {@link TraceStackFrame}, which must in turn be a
	 * successor to {@link TraceStack}. The frame level (an index) must be in the path from stack to
	 * frame. There can be no wildcards between the frame and the register container. For example,
	 * the container for {@code Threads[1]} may be {@code Threads[1].Stack[n].Registers}, where
	 * {@code n} is the frame level. {@code Threads[1].Stack} would have the {@link TraceStack}
	 * interface, {@code Threads[1].Stack[0]} would have the {@link TraceStackFrame} interface, and
	 * {@code Threads[1].Stack[0].Registers} would have the {@link TraceRegisterContainer}
	 * interface. Note it is not sufficient for {@link TraceRegisterContainer} to be a
	 * successor of {@link TraceStack} with a single index between. There <em>must</em> be an
	 * intervening {@link TraceStackFrame}, and the frame level (index) must precede it.
	 * 
	 * @param frameLevel the frame level. May be ignored if not applicable
	 * @param path the path of the seed object relative to the root
	 * @return the filter where the register container should be found, possibly
	 *         {@link PathFilter#NONE}
	 */
	default PathFilter searchForRegisterContainer(int frameLevel, KeyPath path) {
		KeyPath simple = searchForSuitable(TraceRegisterContainer.class, path);
		if (simple != null) {
			return PathFilter.pattern(simple);
		}
		KeyPath stackPath = searchForSuitable(TraceStack.class, path);
		if (stackPath == null) {
			return PathFilter.NONE;
		}
		PathPattern framePatternRelStack =
			getSuccessorSchema(stackPath).searchFor(TraceStackFrame.class, false)
					.getSingletonPattern();
		if (framePatternRelStack == null) {
			return PathFilter.NONE;
		}

		if (framePatternRelStack.countWildcards() != 1) {
			return null;
		}

		Set<PathPattern> patterns = new HashSet<>();
		for (String index : List.of(Integer.toString(frameLevel),
			"0x" + Integer.toHexString(frameLevel))) {
			KeyPath framePathRelStack =
				framePatternRelStack.applyKeys(index).getSingletonPath();
			KeyPath framePath = stackPath.extend(framePathRelStack);
			KeyPath regsPath = searchForSuitable(TraceRegisterContainer.class, framePath);
			if (regsPath != null) {
				patterns.add(new PathPattern(regsPath));
			}
		}
		return PathMatcher.any(patterns.stream());
	}

	/**
	 * Compute the frame level of the object at the given path relative to this schema
	 * 
	 * <p>
	 * If there is no {@link TraceStackFrame} in the path, this will return 0 since it is not
	 * applicable to the object. If there is a stack frame in the path, this will examine its
	 * ancestry, up to and excluding the {@link TraceStack} for an index. If there isn't a stack in
	 * the path, it is assumed to be an ancestor of this schema, meaning the examination will
	 * exhaust the ancestry provided in the path. If no index is found, an exception is thrown,
	 * because the frame level is applicable, but couldn't be computed from the path given. In that
	 * case, the client should include more ancestry in the path. Ideally, this is invoked relative
	 * to the root schema.
	 * 
	 * @param path the path
	 * @return the frame level, or 0 if not applicable
	 * @throws IllegalArgumentException if frame level is applicable but not given in the path
	 */
	default int computeFrameLevel(KeyPath path) {
		KeyPath framePath = searchForAncestor(TraceStackFrame.class, path);
		if (framePath == null) {
			return 0;
		}
		KeyPath stackPath = searchForAncestor(TraceStack.class, framePath);
		for (int i = stackPath == null ? 0 : stackPath.size(); i < framePath.size(); i++) {
			String key = framePath.key(i);
			if (KeyPath.isIndex(key)) {
				return Integer.decode(KeyPath.parseIndex(key));
			}
		}
		throw new IllegalArgumentException("No index between stack and frame");
	}

	/**
	 * Check if this schema can accept a value of the given other schema
	 * 
	 * <p>
	 * This works analogously to {@link Class#isAssignableFrom(Class)}, except that schemas are
	 * quite a bit less flexible. Only {@link PrimitiveTraceObjectSchema#ANY} and
	 * {@link PrimitiveTraceObjectSchema#OBJECT} can accept anything other than exactly themselves.
	 * 
	 * @param that
	 * @return true if an object of that schema can be assigned to this schema.
	 */
	default boolean isAssignableFrom(TraceObjectSchema that) {
		return this.equals(that);
	}
}
