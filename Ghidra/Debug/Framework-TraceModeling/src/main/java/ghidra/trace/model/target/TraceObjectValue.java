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

import com.google.common.collect.Range;

import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject.ConflictResolution;

public interface TraceObjectValue {

	/**
	 * Get the trace containing this value entry
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the parent object of this entry
	 * 
	 * @return the parent
	 */
	TraceObject getParent();

	/**
	 * Get the key identifying this child to its parent
	 * 
	 * @return the key
	 */
	String getEntryKey();

	/**
	 * Get the value
	 * 
	 * @return the value
	 */
	Object getValue();

	/**
	 * Get the value as an object
	 * 
	 * @return the child
	 * @throws ClassCastException if the value is not an object
	 */
	TraceObject getChild();

	/**
	 * Check if this value represents its child's canonical location
	 * 
	 * <p>
	 * The value is canonical if the parent's canonical path extended by this value's key gives the
	 * child's canonical path. If the value is not a child object, the value cannot be canonical.
	 * 
	 * @return true if canonical
	 */
	boolean isCanonical();

	/**
	 * Set the lifespan of this entry, truncating duplicates
	 * 
	 * @param lifespan the new lifespan
	 */
	void setLifespan(Range<Long> lifespan);

	/**
	 * Set the lifespan of this entry
	 * 
	 * <p>
	 * <b>NOTE:</b> For storage efficiency, when expanding the lifespan, the manager may coalesce
	 * this value with intersecting values having equal keys and values. Thus, the resulting
	 * lifespan may be larger than specified.
	 * 
	 * <p>
	 * Values cannot intersect and have the same key, otherwise the value of that key could not be
	 * uniquely determined at a given snap. Thus, when lifespans are being adjusted, such conflicts
	 * must be resolved.
	 * 
	 * @param lifespan the new lifespan
	 * @param resolution specifies how to resolve duplicate keys with intersecting lifespans
	 */
	void setLifespan(Range<Long> span, ConflictResolution resolution);

	/**
	 * Get the lifespan of this entry
	 * 
	 * @return the lifespan
	 */
	Range<Long> getLifespan();

	/**
	 * Set the minimum snap of this entry
	 * 
	 * @see #setLifespan(Range)
	 * @param minSnap the minimum snap, or {@link Long#MIN_VALUE} for "since the beginning of time"
	 */
	void setMinSnap(long minSnap);

	/**
	 * Get the minimum snap of this entry
	 * 
	 * @return the minimum snap, or {@link Long#MIN_VALUE} for "since the beginning of time"
	 */
	long getMinSnap();

	/**
	 * Set the maximum snap of this entry
	 * 
	 * @see #setLifespan(Range)
	 * @param maxSnap the maximum snap, or {@link Long#MAX_VALUE} for "to the end of time"
	 */
	void setMaxSnap(long maxSnap);

	/**
	 * Get the maximum snap of this entry
	 * 
	 * @return the maximum snap, or {@link Long#MAX_VALUE} for "to the end of time"
	 */
	long getMaxSnap();

	/**
	 * Delete this entry
	 * 
	 * <p>
	 * If this entry is part of the child object's canonical path, then the child is also deleted.
	 */
	void delete();

	/**
	 * Delete this entry and, if it is canonical, its successors
	 */
	void deleteTree();

	/**
	 * Check if this value entry has been deleted
	 * 
	 * @return true if the entry has been deleted
	 */
	boolean isDeleted();

	/**
	 * Modify the lifespan or delete this entry, such that it no longer intersects the given span.
	 * 
	 * <p>
	 * If the given span and the current lifespan are already disjoint, this does nothing. If the
	 * given span splits the current lifespan in two, then a new entry is created for the later
	 * lifespan.
	 * 
	 * @param span the span to clear
	 * @return this if the one entry remains, null if the entry is deleted, or the generated entry
	 *         if a second is created.
	 */
	TraceObjectValue truncateOrDelete(Range<Long> span);
}
