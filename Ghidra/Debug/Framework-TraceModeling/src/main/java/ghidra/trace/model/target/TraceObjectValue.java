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

import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.trace.model.Lifespan;
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
	 * Get the "canonical path" of this value
	 * 
	 * <p>
	 * This is the parent's canonical path extended by this value's entry key. Note, in the case
	 * this value has a child object, this is not necessarily its canonical path.
	 * 
	 * @return
	 */
	TraceObjectKeyPath getCanonicalPath();

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
	 * Check if the value is an object (i.e., {@link TraceObject})
	 * 
	 * @return true if an object, false otherwise
	 */
	boolean isObject();

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
	 * Get the (target) schema for the value
	 * 
	 * @return the schema
	 */
	default TargetObjectSchema getTargetSchema() {
		return getParent().getTargetSchema().getChildSchema(getEntryKey());
	}

	/**
	 * Set the lifespan of this entry, truncating duplicates
	 * 
	 * @param lifespan the new lifespan
	 */
	void setLifespan(Lifespan lifespan);

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
	 * @throws DuplicateKeyException if there are denied duplicate keys
	 */
	void setLifespan(Lifespan span, ConflictResolution resolution);

	/**
	 * Get the lifespan of this entry
	 * 
	 * @return the lifespan
	 */
	Lifespan getLifespan();

	/**
	 * Set the minimum snap of this entry
	 * 
	 * @see #setLifespan(Lifespan)
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
	 * @see #setLifespan(Lifespan)
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
	 */
	void delete();

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
	TraceObjectValue truncateOrDelete(Lifespan span);

	/**
	 * Check if the schema designates this value as hidden
	 * 
	 * @return true if hidden
	 */
	default boolean isHidden() {
		TraceObject parent = getParent();
		if (parent == null) {
			return false;
		}
		return parent.getTargetSchema().isHidden(getEntryKey());
	}
}
