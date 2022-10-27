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
import java.util.List;
import java.util.stream.Stream;

import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathPredicates;
import ghidra.trace.model.*;
import ghidra.trace.model.Lifespan.LifeSet;

/**
 * The trace record of an observed {@link TargetObject}
 * 
 * <p>
 * See {@link TargetObject} for information about how objects and the model schema are related in a
 * debugger model. This trace object records a target object and a subset of its children into the
 * database with additional timing information. For objects implementing specific
 * {@link TargetObject} interfaces, a corresponding {@link TraceObjectInterface} can be retrieved.
 * In many cases, such interfaces are just wrappers.
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
	TraceObjectKeyPath getCanonicalPath();

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
	 * Inserts this object at its canonical path for the given lifespan
	 * 
	 * <p>
	 * Any ancestor which does not exist is created. Values' lifespans are added or expanded to
	 * contain the given lifespan. Only the canonical path is considered when looking for existing
	 * ancestry.
	 * 
	 * @param the minimum lifespan of edges from the root to this object
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
		DENY;
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
	 * @param ifClass the class of the interface
	 * @return the interface, or null if not provided
	 */
	<I extends TraceObjectInterface> I queryInterface(Class<I> ifClass);

	/**
	 * Get all values whose child is this object
	 * 
	 * @return the parent values
	 */
	Collection<? extends TraceObjectValue> getParents();

	/**
	 * Get all values (elements and attributes) of this object
	 * 
	 * @return the values
	 */
	Collection<? extends TraceObjectValue> getValues();

	/**
	 * Get values with the given key intersecting the given span
	 * 
	 * @param span the span
	 * @param key the key
	 * @return the collection of values
	 */
	Collection<? extends TraceObjectValue> getValues(Lifespan span, String key);

	/**
	 * Get values with the given key intersecting the given span ordered by time
	 * 
	 * @param span the span
	 * @param key the key
	 * @param forward true to order from least- to most-recent, false for most- to least-recent
	 * @return the stream of values
	 */
	Stream<? extends TraceObjectValue> getOrderedValues(Lifespan span, String key,
			boolean forward);

	/**
	 * Get all elements of this object
	 * 
	 * @return the element values
	 */
	Collection<? extends TraceObjectValue> getElements();

	/**
	 * Get all attributes of this object
	 * 
	 * @return the attribute values
	 */
	Collection<? extends TraceObjectValue> getAttributes();

	/**
	 * Get the value for the given snap and key
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
	 * Stream all ancestor values of this object matching the given predicates, intersecting the
	 * given span
	 * 
	 * @param span a span which values along the path must intersect
	 * @param rootPredicates the predicates for matching path keys, relative to the root
	 * @return the stream of matching paths to values
	 */
	Stream<? extends TraceObjectValPath> getAncestorsRoot(Lifespan span,
			PathPredicates rootPredicates);

	/**
	 * Stream all ancestor values of this object matching the given predicates, intersecting the
	 * given span
	 * 
	 * @param span a span which values along the path must intersect
	 * @param relativePredicates the predicates for matching path keys, relative to this object
	 * @return the stream of matching paths to values
	 */
	Stream<? extends TraceObjectValPath> getAncestors(Lifespan span,
			PathPredicates relativePredicates);

	/**
	 * Stream all successor values of this object matching the given predicates, intersecting the
	 * given span
	 * 
	 * @param span a span which values along the path must intersect
	 * @param relativePredicates the predicates for matching path keys, relative to this object
	 * @return the stream of matching paths to values
	 */
	Stream<? extends TraceObjectValPath> getSuccessors(Lifespan span,
			PathPredicates relativePredicates);

	/**
	 * Stream all successor values of this object at the given relative path, intersecting the given
	 * span, ordered by time.
	 * 
	 * @param span the span which values along the path must intersect
	 * @param relativePath the path relative to this object
	 * @param forward true to order from least- to most-recent, false for most- to least-recent
	 * @return the stream of value paths
	 */
	Stream<? extends TraceObjectValPath> getOrderedSuccessors(Lifespan span,
			TraceObjectKeyPath relativePath, boolean forward);

	/**
	 * Stream all canonical successor values of this object matching the given predicates
	 * 
	 * <p>
	 * If an object has a disjoint life, i.e., multiple canonical parents, then only the
	 * least-recent of those is traversed.
	 * 
	 * @param relativePath the path relative to this object
	 * @return the stream of value paths
	 */
	Stream<? extends TraceObjectValPath> getCanonicalSuccessors(PathPredicates relativePredicates);

	/**
	 * Set a value for the given lifespan
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
	 * truncated or deleted.
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
	 * Get the (target) schema for this object
	 * 
	 * @return the schema
	 */
	TargetObjectSchema getTargetSchema();

	/**
	 * Search for ancestors having the given target interface
	 * 
	 * @param span the span which the found objects must intersect
	 * @param targetIf the interface class
	 * @return the stream of found paths to values
	 */
	Stream<? extends TraceObjectValPath> queryAncestorsTargetInterface(Lifespan span,
			Class<? extends TargetObject> targetIf);

	/**
	 * Search for ancestors providing the given interface and retrieve those interfaces
	 * 
	 * @param <I> the interface type
	 * @param span the span which the found objects must intersect
	 * @param ifClass the interface class
	 * @return the stream of interfaces
	 */
	<I extends TraceObjectInterface> Stream<I> queryAncestorsInterface(Lifespan span,
			Class<I> ifClass);

	/**
	 * Search for ancestors on the canonical path having the given target interface
	 * 
	 * <p>
	 * The object may not yet be inserted at its canonical path
	 * 
	 * @param targetIf the interface class
	 * @return the stream of objects
	 */
	Stream<? extends TraceObject> queryCanonicalAncestorsTargetInterface(
			Class<? extends TargetObject> targetIf);

	/**
	 * Search for ancestors on the canonical path providing the given interface
	 * 
	 * <p>
	 * The object may not yet be inserted at its canonical path
	 * 
	 * @param <I> the interface type
	 * @param ifClass the interface class
	 * @return the stream of interfaces
	 */
	<I extends TraceObjectInterface> Stream<I> queryCanonicalAncestorsInterface(Class<I> ifClass);

	/**
	 * Search for successors providing the given target interface
	 * 
	 * @param span the span which the found paths must intersect
	 * @param targetIf the target interface class
	 * @return the stream of found paths to values
	 */
	Stream<? extends TraceObjectValPath> querySuccessorsTargetInterface(Lifespan span,
			Class<? extends TargetObject> targetIf);

	/**
	 * Search for successors providing the given interface and retrieve those interfaces
	 * 
	 * @param <I> the interface type
	 * @param span the span which the found objects must intersect
	 * @param ifClass the interface class
	 * @return the stream of interfaces
	 */
	<I extends TraceObjectInterface> Stream<I> querySuccessorsInterface(Lifespan span,
			Class<I> ifClass);

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
		if (getTargetSchema().getInterfaces().contains(TargetMethod.class)) {
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
	 * Search for a suitable object having the given target interface
	 * 
	 * <p>
	 * This operates by examining the schema for a unique suitable path, without regard to
	 * lifespans. If needed, the caller should inspect the object's life.
	 * 
	 * @param targetIf the target interface
	 * @return the suitable object, or null if not found
	 */
	default TraceObject querySuitableTargetInterface(Class<? extends TargetObject> targetIf) {
		List<String> path = getRoot().getTargetSchema()
				.searchForSuitable(targetIf, getCanonicalPath().getKeyList());
		if (path == null) {
			return null;
		}
		return getTrace().getObjectManager().getObjectByCanonicalPath(TraceObjectKeyPath.of(path));
	}

	/**
	 * Search for a suitable register container
	 * 
	 * @see TargetObjectSchema#searchForRegisterContainer(int, List)
	 * @param frameLevel the frame level. Must be 0 if not applicable
	 * @return the register container, or null
	 */
	default TraceObject queryRegisterContainer(int frameLevel) {
		PathPredicates regsMatcher = getRoot().getTargetSchema()
				.searchForRegisterContainer(frameLevel, getCanonicalPath().getKeyList());
		for (PathPattern regsPattern : regsMatcher.getPatterns()) {
			TraceObject regsObj = getTrace().getObjectManager()
					.getObjectByCanonicalPath(
						TraceObjectKeyPath.of(regsPattern.getSingletonPath()));
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
	 * {@link TargetExecutionState#INACTIVE}.
	 * 
	 * @param snap the snap
	 * @return the state or null
	 */
	default TargetExecutionState getExecutionState(long snap) {
		TraceObject stateful = querySuitableTargetInterface(TargetExecutionStateful.class);
		if (stateful == null) {
			return null;
		}
		TraceObjectValue stateVal =
			stateful.getAttribute(snap, TargetExecutionStateful.STATE_ATTRIBUTE_NAME);
		if (stateVal == null) {
			return TargetExecutionState.INACTIVE;
		}
		return TargetExecutionState.valueOf((String) stateVal.getValue());
	}
}
