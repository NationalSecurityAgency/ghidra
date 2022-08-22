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

import java.util.List;

import ghidra.dbg.util.PathPredicates;

/**
 * A path of values leading from one object to another
 * 
 * <p>
 * Often, the source object is the root. These are often returned in streams where the search
 * involves a desired "span." The path satisfies that requirement, i.e., "the path intersects the
 * span" if the cumulative intersection of all values' lifespans along the path and the given span
 * is non-empty. Paths may also be empty, implying the source is the destination. Empty paths
 * "intersect" any given span.
 */
public interface TraceObjectValPath extends Comparable<TraceObjectValPath> {
	/**
	 * Get the values in the path, ordered from source to destination
	 * 
	 * @return the list of value entries
	 */
	List<? extends TraceObjectValue> getEntryList();

	/**
	 * Get the keys in the path, ordered from source to destination
	 * 
	 * <p>
	 * The returned list is suited for testing with {@link PathPredicates} or other
	 * path-manipulation methods.
	 * 
	 * @return the list of keys
	 */
	List<String> getKeyList();

	/**
	 * Check if a given value appears on this path
	 * 
	 * @param entry the value entry to check
	 * @return true if it appears on the path, false otherwise
	 */
	boolean contains(TraceObjectValue entry);

	/**
	 * Get the first entry, i.e., the one adjacent to the source object
	 * 
	 * @return the entry, or null if the path is empty
	 */
	TraceObjectValue getFirstEntry();

	/**
	 * Get the source object
	 * 
	 * <p>
	 * This returns the parent object of the first entry of the path, unless the path is empty. If
	 * the path is empty, then this returns the value passed in {@code ifEmpty}, which is presumably
	 * the destination object.
	 * 
	 * @param ifEmpty the object to return when this path is empty
	 * @return the source object
	 */
	TraceObject getSource(TraceObject ifEmpty);

	/**
	 * Get the last entry, i.e., the one adjacent to the destination object
	 * 
	 * @return the entry, or null if the path is empty
	 */
	TraceObjectValue getLastEntry();

	/**
	 * Get the destination value
	 * 
	 * <p>
	 * This returns the value of the last entry of the path, unless the path is empty. If the path
	 * is empty, then this returns the object passed in {@code ifEmpty}, which is presumably the
	 * source object. Note that values may be a primitive, so the destination is not always an
	 * object, i.e., {@link TraceObject}. Use {@link #getDestination(TraceObject)} to assume the
	 * destination is an object.
	 * 
	 * @param ifEmpty the value to return when the path is empty
	 * @return the destination value
	 */
	Object getDestinationValue(Object ifEmpty);

	/**
	 * Get the destination object
	 * 
	 * <p>
	 * This returns the child object of the last entry of the path, unless the path is empty. If the
	 * path is empty, then this returns the object passed in {@code ifEmpty}, which is presumably
	 * the source object. Note that values may be primitive, so the destination is not always an
	 * object, i.e., {@link TraceObject}. Use {@link #getDestinationValue(Object)} when it is not
	 * safe to assume the destination is an object.
	 * 
	 * @param ifEmpty the object to return when the path is empty
	 * @return the destination object
	 * @throws ClassCastException if the destination value is not an object
	 */
	TraceObject getDestination(TraceObject ifEmpty);
}
