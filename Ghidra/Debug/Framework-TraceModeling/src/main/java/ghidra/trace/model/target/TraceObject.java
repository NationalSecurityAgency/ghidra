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

import com.google.common.collect.Range;

import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathPredicates;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceUniqueObject;

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
	 * Inserts this object at its canonical path for its lifespan
	 * 
	 * <p>
	 * Any ancestor which does not exist is created with the same lifespan as this object. Values
	 * are set with the same lifespan. Only the canonical path is considered when looking for
	 * existing ancestry. Any whose lifespan intersects that of this object is considered
	 * "existing." If an existing ancestor is detached, this object will still become its successor,
	 * and the resulting subtree will remain detached.
	 * 
	 * @param resolution the rule for handling duplicate keys when setting values.
	 */
	void insert(ConflictResolution resolution);

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
	Stream<TraceObjectValPath> getAllPaths(Range<Long> span);

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
		 * Throw an exception if the specified lifespan would result in conflicting entries
		 */
		DENY;
	}

	/**
	 * Set the lifespan of this object
	 * 
	 * <p>
	 * NOTE: Objects with intersecting lifespans are not checked for duplicate canonical paths.
	 * However, their parent value entries are checked for conflicts. Thus, at any snap, it is
	 * impossible for any two objects with equal canonical paths to both exist at their canonical
	 * locations.
	 * 
	 * @param lifespan the new lifespan
	 */
	void setLifespan(Range<Long> lifespan);

	/**
	 * Get the lifespan of this object
	 * 
	 * @return the lifespan
	 */
	Range<Long> getLifespan();

	/**
	 * Set the minimum snap of this object
	 * 
	 * @see #setLifespan(Range)
	 * @param minSnap the minimum snap, or {@link Long#MIN_VALUE} for "since the beginning of time"
	 */
	void setMinSnap(long minSnap);

	/**
	 * Get the minimum snap of this object
	 * 
	 * @return the minimum snap, or {@link Long#MIN_VALUE} for "since the beginning of time"
	 */
	long getMinSnap();

	/**
	 * Set the maximum snap of this object
	 * 
	 * @see #setLifespan(Range)
	 * @param maxSnap the maximum snap, or {@link Long#MAX_VALUE} for "to the end of time"
	 */
	void setMaxSnap(long maxSnap);

	/**
	 * Get the maximum snap of this object
	 * 
	 * @return the maximum snap, or {@link Long#MAX_VALUE} for "to the end of time"
	 */
	long getMaxSnap();

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
	 * Get values with the given key intersecting the given span ordered by time
	 * 
	 * @param span the span
	 * @param key the key
	 * @param forward true to order from least- to most-recent, false for most- to least-recent
	 * @return the stream of values
	 */
	Stream<? extends TraceObjectValue> getOrderedValues(Range<Long> span, String key,
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
	Stream<? extends TraceObjectValPath> getAncestors(Range<Long> span,
			PathPredicates rootPredicates);

	/**
	 * Stream all successor values of this object matching the given predicates, intersecting the
	 * given span
	 * 
	 * @param span a span which values along the path must intersect
	 * @param relativePredicates the predicates for matching path keys, relative to this object
	 * @return the stream of matching paths to values
	 */
	Stream<? extends TraceObjectValPath> getSuccessors(Range<Long> span,
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
	Stream<? extends TraceObjectValPath> getOrderedSuccessors(Range<Long> span,
			TraceObjectKeyPath relativePath, boolean forward);

	/**
	 * Set a value for the given lifespan
	 * 
	 * @param lifespan the lifespan of the value
	 * @param key the key to set
	 * @param value the new value
	 * @param resolution determines how to resolve conflicting keys with intersecting lifespans
	 * @return the created value entry
	 */
	TraceObjectValue setValue(Range<Long> lifespan, String key, Object value,
			ConflictResolution resolution);

	/**
	 * Set a value for the given lifespan, truncating existing entries
	 * 
	 * @param lifespan the lifespan of the value
	 * @param key the key to set
	 * @param value the new value
	 * @return the created value entry
	 */
	TraceObjectValue setValue(Range<Long> lifespan, String key, Object value);

	/**
	 * Set an attribute for the given lifespan
	 * 
	 * <p>
	 * This is equivalent to {@link #setValue(Range, String, Object)}, except it verifies the key is
	 * an attribute name.
	 * 
	 * @param lifespan the lifespan of the attribute
	 * @param name the name to set
	 * @param value the new value
	 * @return the created value entry
	 */
	TraceObjectValue setAttribute(Range<Long> lifespan, String name, Object value);

	/**
	 * Set an element for the given lifespan
	 * 
	 * <p>
	 * This is equivalent to {@link #setValue(Range, String, Object)}, except it converts the index
	 * to a key, i.e., add brackets.
	 * 
	 * @param lifespan the lifespan of the element
	 * @param index the index to set
	 * @param value the new value
	 * @return the created value entry
	 */
	TraceObjectValue setElement(Range<Long> lifespan, String index, Object value);

	/**
	 * Set an element for the given lifespan
	 * 
	 * @param lifespan the lifespan of the element
	 * @param index the index to set
	 * @param value the new value
	 * @return the created value entry
	 */
	TraceObjectValue setElement(Range<Long> lifespan, long index, Object value);

	/**
	 * Get the (target) schema for this object
	 * 
	 * @return the schema
	 */
	TargetObjectSchema getTargetSchema();

	/**
	 * Search for ancestors providing the given interface and retrieve those interfaces
	 * 
	 * @param <I> the interface type
	 * @param span the span which the found objects must intersect
	 * @param ifClass the interface class
	 * @return the stream of interfaces
	 */
	<I extends TraceObjectInterface> Stream<I> queryAncestorsInterface(Range<Long> span,
			Class<I> ifClass);

	/**
	 * Search for ancestors on the canonical path providing the given interface
	 * 
	 * <p>
	 * The object may not yet be inserted at its canonical path
	 * 
	 * @param <I> the interface type
	 * @param span the span which the found objects must intersect
	 * @param ifClass the interface class
	 * @return the stream of interfaces
	 */
	<I extends TraceObjectInterface> Stream<I> queryCanonicalAncestorsInterface(
			Range<Long> span, Class<I> ifClass);

	/**
	 * Search for successors providing the given interface and retrieve those interfaces
	 * 
	 * @param <I> the interface type
	 * @param span the span which the found objects must intersect
	 * @param ifClass the interface class
	 * @return the stream of interfaces
	 */
	<I extends TraceObjectInterface> Stream<I> querySuccessorsInterface(Range<Long> span,
			Class<I> ifClass);

	/**
	 * Delete this object along with parent and child value entries referring to it
	 * 
	 * <p>
	 * Note, this does not delete the children or any successors. Use {@link #deleteTree()} to
	 * delete an entire subtree, regardless of lifespan. It is not recommended to invoke this on the
	 * root object, since it cannot be replaced without first clearing the manager.
	 */
	void delete();

	/**
	 * Delete this object and its successors along with value entries referring to any
	 * 
	 * <p>
	 * It is not recommended to invoke this on the root object. Instead, use
	 * {@link TraceObjectManager#clear()}. The root object cannot be replaced without first clearing
	 * the manager.
	 */
	void deleteTree();

	/**
	 * Check if this object has been deleted
	 * 
	 * @return true if the object has been deleted
	 */
	@Override
	boolean isDeleted();

	/**
	 * Modify the lifespan or delete this object, such that it no longer intersects the given span.
	 * 
	 * <p>
	 * If the given span and the current lifespan are already disjoint, this does nothing. If the
	 * given span splits the current lifespan in two, an exception is thrown. This is because the
	 * two resulting objects ought to be identical, but they cannot be. Instead the one object
	 * should remain alive, and the edge(s) pointing to it should be truncated. In other words, a
	 * single object cannot vanish and then later re-appear, but it can be unlinked and then later
	 * become relinked.
	 * 
	 * @param span the span to clear
	 * @return this if the one object remains, null if the object is deleted.
	 * @throws IllegalArgumentException if the given span splits the current lifespan in two
	 */
	TraceObject truncateOrDelete(Range<Long> span);
}
