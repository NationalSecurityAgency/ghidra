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
package ghidra.trace.model.target;

import java.util.Collection;
import java.util.stream.Stream;

import ghidra.trace.model.*;
import ghidra.trace.model.Lifespan.LifeSet;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.target.iface.*;
import ghidra.trace.model.target.path.*;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.model.thread.TraceProcess;
import ghidra.trace.model.thread.TraceThread;

/**
 * A record of a target object in a debugger
 * 
 * <p>
 * This object supports querying for and obtaining the interfaces which constitute what the object
 * is and define how the client may interact with it. The object may also have children, e.g., a
 * process should likely have threads.
 * 
 * <p>
 * This interface is the focal point of the "debug target model." A debugger may present itself as
 * an arbitrary directory of "target objects." The root object is typically the debugger's session,
 * and one its attributes is a collection for its attached targets. These objects, including the
 * root object, may implement any number of interfaces extending {@link TraceObjectInterface}. These
 * interfaces comprise the type and behavior of the object. An object's children comprise its
 * elements (for collection-like objects) and attributes. Every object in the directory has a path.
 * Each element ("key") in the path identifies an index (if the child is an element) or a name (if
 * the child is an attribute). It is the implementation's responsibility to ensure each object's
 * path correctly identifies that same object in the model directory. The root has the empty path.
 * Every object must have a unique path; thus, every object must have a unique key among its
 * sibling.
 * 
 * <p>
 * The objects are arranged in a directory with links permitted. Links come in the form of
 * object-valued attributes or elements where the path does not match the object value's path. Thus,
 * the overall structure remains a tree, but by resolving links, the model may be treated as a
 * directed graph, likely containing cycles.
 * 
 * <p>
 * The implementation must guarantee that distinct {@link TraceObject}s from the same model do not
 * share the same path. That is, checking for object identity is sufficient to check that two
 * variables refer to the same object.
 * 
 * <p>
 * Various conventions govern where the client/user should search to obtain a given interface in the
 * context of some target object. For example, if the user is interacting with a thread, and wishes
 * to access that thread's memory, it needs to follow a given search order to find the appropriate
 * target object(s), if they exist, implementing the desired interface. See
 * {@link TraceObjectSchema#searchForSuitable(TraceObjectSchema, KeyPath)} for details. In summary,
 * the order is:
 * 
 * <ol>
 * <li><b>The object itself:</b> Test if the context target object supports the desired interface.
 * If it does, take it.</li>
 * <li><b>Aggregate objects:</b> If the object is marked with {@link TraceAggregate}, collect
 * all attributes supporting the desired interface. If there are any, take them. This step is
 * applied recursively if any child attribute is also marked with {@link TraceAggregate}.</li>
 * <li><b>Ancestry:</b> Apply these same steps to the object's (canonical) parent, recursively.</li>
 * </ol>
 * 
 * <p>
 * For some situations, exactly one object is required. In that case, take the first obtained by
 * applying the above rules. In other situations, multiple objects may be acceptable. Again, apply
 * the rules until a sufficient collection of objects is obtained. If an object is in conflict with
 * another, take the first encountered. This situation may be appropriate if, e.g., multiple target
 * memories present disjoint regions. There should not be conflicts among sibling. If there are,
 * then either the model or the query is not sound. The order siblings considered should not matter.
 * 
 * <p>
 * This relatively free structure and corresponding conventions allow for debuggers to present a
 * model which closely reflects the structure of its session. For example, the following structure
 * may be presented by a user-space debugger for a desktop operating system:
 * 
 * <ul>
 * <li>"Session" : {@link TraceObject}</li>
 * <ul>
 * <li>"Process 789" : {@link TraceProcess}, {@link TraceAggregate}</li>
 * <ul>
 * <li>"Threads" : {@link TraceObject}</li>
 * <ul>
 * <li>"Thread 1" : {@link TraceThread}, {@link TraceExecutionStateful},
 * {@link TraceAggregate}</li>
 * <ul>
 * <li>"Registers" : {@link TraceRegisterContainer}</li>
 * <ul>
 * <li>"r1" : {@link TraceRegister}</li>
 * <li>...</li>
 * </ul>
 * </ul>
 * <li>...more threads</li>
 * </ul>
 * <li>"Memory" : {@link TraceMemory}</li>
 * <ul>
 * <li>"[0x00400000:0x00401234]" : {@link TraceMemoryRegion}</li>
 * <li>...more regions</li>
 * </ul>
 * <li>"Modules" : {@link TraceObject}</li>
 * <ul>
 * <li>"/usr/bin/echo" : {@link TraceModule}</li>
 * <ul>
 * <li>".text" : {@link TraceSection}</li>
 * <li>...more sections</li>
 * </ul>
 * <li>...more modules</li>
 * </ul>
 * </ul>
 * <li>"Environment": {@link TraceEnvironment}</li>
 * <ul>
 * <li>"Process 321" : {@link TraceObject}</li>
 * <li>...more processes</li>
 * </ul>
 * </ul>
 * </ul>
 * 
 * <p>
 * Note that this interface does not provide target-related operations, but only a means of
 * modifying the database. The target connector, if this trace is still "live," should have a handle
 * to this same trace and so can update the records as events occur in the debugger session and keep
 * the target state up to date. Commands for manipulating the target and/or session itself are
 * provided by that connector.
 */
public interface TraceObject extends TraceUniqueObject {
	String EXTRA_INTERFACES_ATTRIBUTE_NAME = "_extra_ifs";

	/**
	 * Get the trace containing this object
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the database key for this object
	 * 
	 * @return the key
	 */
	long getKey();

	/**
	 * Get the root of the tree containing this object
	 * 
	 * @return the root
	 */
	TraceObject getRoot();

	/**
	 * Get the canonical path of this object
	 * 
	 * @return the path
	 */
	KeyPath getCanonicalPath();

	/**
	 * Get all ranges of this object's life
	 * 
	 * <p>
	 * Essentially, this is the union of the lifespans of all canonical parent values
	 * 
	 * @return the range set for snaps at which this object is considered "inserted."
	 */
	LifeSet getLife();

	/**
	 * Check if the object is alive at the given snap
	 * 
	 * <p>
	 * This is preferable to {@link #getLife()}, when we only need to check one snap
	 * 
	 * @param snap the snap
	 * @return true if alive, false if not
	 */
	boolean isAlive(long snap);

	/**
	 * Check if the object is alive at all in the given span
	 * 
	 * @param span the span
	 * @return true if alive, false if not
	 */
	boolean isAlive(Lifespan span);

	/**
	 * Inserts this object at its canonical path for the given lifespan
	 * 
	 * <p>
	 * Any ancestor which does not exist is created. Values' lifespans are added or expanded to
	 * contain the given lifespan. Only the canonical path is considered when looking for existing
	 * ancestry.
	 * 
	 * @param lifespan the minimum lifespan of edges from the root to this object
	 * @param resolution the rule for handling duplicate keys when setting values.
	 * @return the value path from root to the newly inserted object
	 */
	TraceObjectValPath insert(Lifespan lifespan, ConflictResolution resolution);

	/**
	 * Remove this object from its canonical path for the given lifespan
	 * 
	 * <p>
	 * Truncate the lifespans of this object's canonical parent value by the given span. If the
	 * parent value's lifespan is contained in the given span, the parent value will be deleted.
	 * 
	 * @param span the span during which this object should be removed
	 */
	void remove(Lifespan span);

	/**
	 * Remove this object and its successors from their canonical paths for the given span
	 * 
	 * <p>
	 * Truncate the lifespans of this object's parent values and all canonical values succeeding
	 * this object. If a truncated value's lifespan is contained in the given span, the value will
	 * be deleted.
	 * 
	 * @param span the span during which this object and its canonical successors should be removed
	 */
	void removeTree(Lifespan span);

	/**
	 * Get the parent value along this object's canonical path for a given snapshot
	 * 
	 * <p>
	 * To be the canonical parent value at a given snapshot, three things must be true: 1) The
	 * parent object must have this object's path with the final key removed. 2) The parent value's
	 * entry key must be equal to the final key of this object's path. 3) The value's lifespan must
	 * contain the given snapshot. If no value satisfies these, null is returned, and the object and
	 * its subtree are said to be "detached" at the given snapshot.
	 * 
	 * @param snap the snapshot key
	 * @return the canonical parent value, or null
	 */
	TraceObjectValue getCanonicalParent(long snap);

	/**
	 * Get the parent values along this object's canonical path for a given lifespan
	 * 
	 * <p>
	 * To be a canonical parent in a given lifespan, three things must be true: 1) The parent object
	 * must have this object's path with the final key removed. 2) The parent value's entry key must
	 * be equal to the final key of this object's path. 3) The value's lifespan must intersect the
	 * given lifespan. If the result is empty, the object and its subtree are said to be "detatched"
	 * during the given lifespan.
	 * 
	 * @param lifespan the lifespan to consider
	 * @return the stream of canonical parents
	 */
	Stream<? extends TraceObjectValue> getCanonicalParents(Lifespan lifespan);

	/**
	 * Check if this object is the root
	 * 
	 * @return true if root
	 */
	boolean isRoot();

	/**
	 * Get all paths actually leading to this object, from the root, within the given span
	 * 
	 * <p>
	 * Aliased keys are excluded.
	 * 
	 * @param span the span which every value entry on each path must intersect
	 * @return the paths
	 */
	Stream<? extends TraceObjectValPath> getAllPaths(Lifespan span);

	/**
	 * Specifies a strategy for resolving duplicate keys
	 * 
	 * <p>
	 * Values are not permitted to have intersecting lifespans if they have the same parent and key,
	 * since this would imply the value is not unique for a given parent, key, and snap. Thus, when
	 * values and lifespans are being set that would result in conflicting entries, the conflict
	 * must be resolved, either by clearing the span or by denying the change.
	 */
	enum ConflictResolution {
		/**
		 * Truncate, split, or delete conflicting entries to make way for the specified lifespan
		 */
		TRUNCATE,
		/**
		 * Throw {@link DuplicateKeyException} if the specified lifespan would result in conflicting
		 * entries
		 */
		DENY,
		/**
		 * Adjust the new entry to fit into the span available, possibly ignoring it altogether
		 */
		ADJUST;
	}

	/**
	 * Get all the interface classes provided by this object, according to the schema
	 * 
	 * @return the collection of interface classes
	 */
	Collection<Class<? extends TraceObjectInterface>> getInterfaces();

	/**
	 * Request the specified interface provided by this object
	 * 
	 * @param <I> the type of the interface
	 * @param iface the class of the interface
	 * @return the interface, or null if not provided
	 */
	<I extends TraceObjectInterface> I queryInterface(Class<I> iface);

	/**
	 * Get all values intersecting the given span and whose child is this object
	 * 
	 * <p>
	 * Aliased keys are excluded.
	 * 
	 * @param span the span
	 * @return the parent values
	 */
	Collection<? extends TraceObjectValue> getParents(Lifespan span);

	/**
	 * Get all values (elements and attributes) of this object intersecting the given span
	 * 
	 * <p>
	 * Aliased keys are excluded.
	 * 
	 * @param span the span
	 * @return the values
	 */
	Collection<? extends TraceObjectValue> getValues(Lifespan span);

	/**
	 * Get values with the given key intersecting the given span
	 * 
	 * <p>
	 * If the key is an alias, the target key's values are retrieved instead.
	 * 
	 * @param span the span
	 * @param key the key
	 * @return the collection of values
	 */
	Collection<? extends TraceObjectValue> getValues(Lifespan span, String key);

	/**
	 * Get values with the given key intersecting the given span ordered by time
	 * 
	 * <p>
	 * If the key is an alias, the target key's values are retrieved instead.
	 * 
	 * @param span the span
	 * @param key the key
	 * @param forward true to order from least- to most-recent, false for most- to least-recent
	 * @return the stream of values
	 */
	Stream<? extends TraceObjectValue> getOrderedValues(Lifespan span, String key,
			boolean forward);

	/**
	 * Get all elements of this object intersecting the given span
	 * 
	 * @param span the span
	 * @return the element values
	 */
	Collection<? extends TraceObjectValue> getElements(Lifespan span);

	/**
	 * Get all attributes of this object intersecting the given span
	 * 
	 * <p>
	 * Aliased keys are excluded.
	 * 
	 * @param span the span
	 * @return the attribute values
	 */
	Collection<? extends TraceObjectValue> getAttributes(Lifespan span);

	/**
	 * Get the value for the given snap and key
	 * 
	 * <p>
	 * If the key is an alias, the target key's value is retrieved instead.
	 * 
	 * @param snap the snap
	 * @param key the key
	 * @return the value entry
	 */
	TraceObjectValue getValue(long snap, String key);

	/**
	 * Get the value for the given snap and element index
	 * 
	 * <p>
	 * This is equivalent to {@link #getValue(long, String)}, but converts index to a key, i.e.,
	 * adds brackets.
	 * 
	 * @param snap the snap
	 * @param index the index
	 * @return the value entry
	 */
	TraceObjectValue getElement(long snap, String index);

	/**
	 * Get the value for the given snap and element index
	 * 
	 * <p>
	 * This is equivalent to {@link #getElement(long, String)}, but converts index to a string in
	 * decimal.
	 * 
	 * @param snap the snap
	 * @param index the index
	 * @return the value entry
	 */
	TraceObjectValue getElement(long snap, long index);

	/**
	 * Get the value for the given snap and attribute name
	 * 
	 * <p>
	 * This is equivalent to {@link #getValue(long, String)}, except it validates that name is not
	 * an index.
	 * 
	 * @param snap the snap
	 * @param name the name
	 * @return the value entry
	 */
	TraceObjectValue getAttribute(long snap, String name);

	/**
	 * Stream all ancestor values of this object matching the given filter, intersecting the given
	 * span
	 * 
	 * <p>
	 * Aliased keys are excluded. The filter should be formulated to use the aliases' target
	 * attributes.
	 * 
	 * @param span a span which values along the path must intersect
	 * @param rootFilter the filter for matching path keys, relative to the root
	 * @return the stream of matching paths to values
	 */
	Stream<? extends TraceObjectValPath> getAncestorsRoot(Lifespan span,
			PathFilter rootFilter);

	/**
	 * Stream all ancestor values of this object matching the given filter, intersecting the given
	 * span
	 * 
	 * <p>
	 * Aliased keys are excluded. The filter should be formulated to use the aliases' target
	 * attributes.
	 * 
	 * @param span a span which values along the path must intersect
	 * @param relativeFilter the filter for matching path keys, relative to this object
	 * @return the stream of matching paths to values
	 */
	Stream<? extends TraceObjectValPath> getAncestors(Lifespan span,
			PathFilter relativeFilter);

	/**
	 * Stream all successor values of this object matching the given filter, intersecting the given
	 * span
	 * 
	 * <p>
	 * Aliased keys are excluded. The filter should be formulated to use the aliases' target
	 * attributes.
	 * 
	 * @param span a span which values along the path must intersect
	 * @param relativeFilter the filter for matching path keys, relative to this object
	 * @return the stream of matching paths to values
	 */
	Stream<? extends TraceObjectValPath> getSuccessors(Lifespan span,
			PathFilter relativeFilter);

	/**
	 * Stream all successor values of this object at the given relative path, intersecting the given
	 * span, ordered by time.
	 * 
	 * <p>
	 * Aliased keys are excluded. The filter should be formulated to use the aliases' target
	 * attributes.
	 * 
	 * @param span the span which values along the path must intersect
	 * @param relativePath the path relative to this object
	 * @param forward true to order from least- to most-recent, false for most- to least-recent
	 * @return the stream of value paths
	 */
	Stream<? extends TraceObjectValPath> getOrderedSuccessors(Lifespan span,
			KeyPath relativePath, boolean forward);

	/**
	 * Stream all canonical successor values of this object matching the given filter
	 * 
	 * <p>
	 * If an object has a disjoint life, i.e., multiple canonical parents, then only the
	 * least-recent of those is traversed. Aliased keys are excluded; those can't be canonical
	 * anyway. By definition, a primitive value is not canonical, even if it is the final value in
	 * the path.
	 * 
	 * @param relativeFilter filter on the relative path from this object to desired successors
	 * @return the stream of value paths
	 */
	Stream<? extends TraceObjectValPath> getCanonicalSuccessors(PathFilter relativeFilter);

	/**
	 * Set a value for the given lifespan
	 * 
	 * <p>
	 * If the key is an alias, the target key's value is set instead.
	 * 
	 * @param lifespan the lifespan of the value
	 * @param key the key to set
	 * @param value the new value
	 * @param resolution determines how to resolve duplicate keys with intersecting lifespans
	 * @return the created value entry
	 * @throws DuplicateKeyException if there are denied duplicate keys
	 */
	TraceObjectValue setValue(Lifespan lifespan, String key, Object value,
			ConflictResolution resolution);

	/**
	 * Set a value for the given lifespan, truncating existing entries
	 * 
	 * <p>
	 * Setting a value of {@code null} effectively deletes the value for the given lifespan and
	 * returns {@code null}. Values of the same key intersecting the given lifespan or either
	 * truncated or deleted. If the key is an alias, the target key's value is set instead.
	 * 
	 * 
	 * @param lifespan the lifespan of the value
	 * @param key the key to set
	 * @param value the new value
	 * @return the created value entry, or null
	 */
	TraceObjectValue setValue(Lifespan lifespan, String key, Object value);

	/**
	 * Set an attribute for the given lifespan
	 * 
	 * <p>
	 * This is equivalent to {@link #setValue(Lifespan, String, Object)}, except it verifies the key
	 * is an attribute name.
	 * 
	 * @param lifespan the lifespan of the attribute
	 * @param name the name to set
	 * @param value the new value
	 * @return the created value entry
	 */
	TraceObjectValue setAttribute(Lifespan lifespan, String name, Object value);

	/**
	 * Set an element for the given lifespan
	 * 
	 * <p>
	 * This is equivalent to {@link #setValue(Lifespan, String, Object)}, except it converts the
	 * index to a key, i.e., add brackets.
	 * 
	 * @param lifespan the lifespan of the element
	 * @param index the index to set
	 * @param value the new value
	 * @return the created value entry
	 */
	TraceObjectValue setElement(Lifespan lifespan, String index, Object value);

	/**
	 * Set an element for the given lifespan
	 * 
	 * @param lifespan the lifespan of the element
	 * @param index the index to set
	 * @param value the new value
	 * @return the created value entry
	 */
	TraceObjectValue setElement(Lifespan lifespan, long index, Object value);

	/**
	 * Get the schema for this object
	 * 
	 * @return the schema
	 */
	TraceObjectSchema getSchema();

	/**
	 * Search for ancestors having the given interface
	 * 
	 * @param span the span which the found objects must intersect
	 * @param iface the interface class
	 * @return the stream of found paths to values
	 */
	Stream<? extends TraceObjectValPath> findAncestorsInterface(Lifespan span,
			Class<? extends TraceObjectInterface> iface);

	/**
	 * Search for ancestors having the given interface and retrieve those interfaces
	 * 
	 * @param <I> the interface type
	 * @param span the span which the found objects must intersect
	 * @param iface the interface class
	 * @return the stream of interfaces
	 */
	<I extends TraceObjectInterface> Stream<I> queryAncestorsInterface(Lifespan span,
			Class<I> iface);

	/**
	 * Search for ancestors on the canonical path having the given interface
	 * 
	 * <p>
	 * The object may not yet be inserted at its canonical path.
	 * 
	 * @param iface the interface class
	 * @return the stream of objects
	 */
	Stream<? extends TraceObject> findCanonicalAncestorsInterface(
			Class<? extends TraceObjectInterface> iface);

	/**
	 * Search for ancestors on the canonical path having the given interface and retrieve those
	 * interfaces
	 * 
	 * <p>
	 * The object may not yet be inserted at its canonical path.
	 * 
	 * @param <I> the interface type
	 * @param iface the interface class
	 * @return the stream of interfaces
	 */
	<I extends TraceObjectInterface> Stream<I> queryCanonicalAncestorsInterface(Class<I> iface);

	/**
	 * Search for successors having the given interface
	 * 
	 * @param span the span which the found paths must intersect
	 * @param iface the interface class
	 * @param requireCanonical if the objects must be found within their canonical container
	 * @return the stream of found paths to values
	 */
	Stream<? extends TraceObjectValPath> findSuccessorsInterface(Lifespan span,
			Class<? extends TraceObjectInterface> iface, boolean requireCanonical);

	/**
	 * Search for successors having the given interface and retrieve those interfaces
	 * 
	 * @param <I> the interface type
	 * @param span the span which the found objects must intersect
	 * @param iface the interface class
	 * @param requireCanonical if the objects must be found within their canonical container
	 * @return the stream of interfaces
	 */
	<I extends TraceObjectInterface> Stream<I> querySuccessorsInterface(Lifespan span,
			Class<I> iface, boolean requireCanonical);

	/**
	 * Delete this object along with parent and child value entries referring to it
	 * 
	 * <p>
	 * <b>Warning:</b> This will remove the object from the manager <em>entirely</em>, not just over
	 * a given span. In general, this is used for cleaning and maintenance. Consider
	 * {@link #remove(Lifespan)} or {@link TraceObjectValue#delete()} instead. Note, this does not
	 * delete the child objects or any successors. It is not recommended to invoke this on the root
	 * object, since it cannot be replaced without first clearing the manager.
	 */
	void delete();

	/**
	 * Check if this object has been deleted
	 * 
	 * @return true if the object has been deleted
	 */
	@Override
	boolean isDeleted();

	/**
	 * Check if the child represents a method at the given snap
	 * 
	 * @param snap the snap
	 * @return true if a method
	 */
	default boolean isMethod(long snap) {
		if (getSchema().getInterfaces().contains(TraceMethod.class)) {
			return true;
		}
		TraceObjectValue extras = getAttribute(snap, TraceObject.EXTRA_INTERFACES_ATTRIBUTE_NAME);
		if (extras == null) {
			return false;
		}
		Object val = extras.getValue();
		if (!(val instanceof String)) {
			return false;
		}
		String valStr = (String) val;
		// Not ideal, but it's not a substring of any other schema interface....
		if (valStr.contains("Method")) {
			return true;
		}
		return false;
	}

	/**
	 * Search for a suitable object having the given interface
	 * 
	 * <p>
	 * This operates by examining the schema for a unique suitable path, without regard to
	 * lifespans. If needed, the caller should inspect the object's life.
	 * 
	 * @param iface the interface
	 * @return the suitable object, or null if not found
	 */
	default TraceObject findSuitableInterface(Class<? extends TraceObjectInterface> iface) {
		if (iface == TraceObjectInterface.class) {
			return this;
		}
		KeyPath path = getRoot().getSchema().searchForSuitable(iface, getCanonicalPath());
		if (path == null) {
			return null;
		}
		return getTrace().getObjectManager().getObjectByCanonicalPath(path);
	}

	/**
	 * Search for a suitable canonical container of the given interface
	 * 
	 * @param iface the interface
	 * @return the container, or null if not found
	 */
	default TraceObject findSuitableContainerInterface(
			Class<? extends TraceObjectInterface> iface) {
		KeyPath path = getRoot().getSchema().searchForSuitableContainer(iface, getCanonicalPath());
		if (path == null) {
			return null;
		}
		return getTrace().getObjectManager().getObjectByCanonicalPath(path);
	}

	/**
	 * Search for a suitable object having the given schema
	 * 
	 * <p>
	 * This operates by examining the schema for a unique suitable path, without regard to
	 * lifespans. If needed, the caller should inspect the object's life.
	 * 
	 * @param schema the schema
	 * @return the suitable object, or null if not found
	 */
	default TraceObject findSuitableSchema(TraceObjectSchema schema) {
		KeyPath path = getRoot().getSchema().searchForSuitable(schema, getCanonicalPath());
		if (path == null) {
			return null;
		}
		return getTrace().getObjectManager().getObjectByCanonicalPath(path);
	}

	/**
	 * Search for a suitable register container
	 * 
	 * @see TraceObjectSchema#searchForRegisterContainer(int, KeyPath)
	 * @param frameLevel the frame level. Must be 0 if not applicable
	 * @return the register container, or null
	 */
	default TraceObject findRegisterContainer(int frameLevel) {
		PathFilter regsMatcher =
			getRoot().getSchema().searchForRegisterContainer(frameLevel, getCanonicalPath());
		for (PathPattern regsPattern : regsMatcher.getPatterns()) {
			TraceObject regsObj = getTrace().getObjectManager()
					.getObjectByCanonicalPath(regsPattern.getSingletonPath());
			if (regsObj != null) {
				return regsObj;
			}
		}
		return null;
	}

	/**
	 * Get the execution state, if applicable, of this object
	 * 
	 * <p>
	 * This searches for the conventional stateful object defining this object's execution state. If
	 * such an object does not exist, null is returned. If one does exist, then its execution state
	 * at the given snap is returned. If that state is null, it is assumed
	 * {@link TraceExecutionState#INACTIVE}.
	 * 
	 * @param snap the snap
	 * @return the state or null
	 */
	default TraceExecutionState getExecutionState(long snap) {
		TraceObject stateful = findSuitableInterface(TraceExecutionStateful.class);
		if (stateful == null) {
			return null;
		}
		TraceObjectValue stateVal =
			stateful.getAttribute(snap, TraceExecutionStateful.KEY_STATE);
		if (stateVal == null) {
			return TraceExecutionState.INACTIVE;
		}
		return TraceExecutionState.valueOf(stateVal.castValue());
	}
}
