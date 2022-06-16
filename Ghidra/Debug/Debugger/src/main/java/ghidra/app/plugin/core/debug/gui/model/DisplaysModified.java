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
package ghidra.app.plugin.core.debug.gui.model;

import java.util.Objects;

import com.google.common.collect.Range;

import ghidra.dbg.util.PathPredicates;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;

public interface DisplaysModified {
	/**
	 * Get the current trace
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the current snap
	 * 
	 * @return the snap
	 */
	long getSnap();

	/**
	 * Get the trace for comparison, which may be the same as the current trace
	 * 
	 * @return the trace, or null to disable comparison
	 */
	Trace getDiffTrace();

	/**
	 * Get the snap for comparison
	 * 
	 * @return the snap
	 */
	long getDiffSnap();

	/**
	 * Determine whether two objects differ
	 * 
	 * <p>
	 * By default the objects are considered equal if their canonical paths agree, without regard to
	 * the source trace or child values. To compare child values would likely recurse all the way to
	 * the leaves, which is costly and not exactly informative. This method should only be called
	 * for objects at the same path, meaning the two objects have at least one path in common. If
	 * this path is the canonical path, then the two objects (by default) cannot differ. This will
	 * detect changes in object links, though.
	 * 
	 * @param newObject the current object
	 * @param oldObject the previous object
	 * @return true if the objects differ, i.e., should be displayed in red
	 */
	default boolean isObjectsDiffer(TraceObject newObject, TraceObject oldObject) {
		if (newObject == oldObject) {
			return false;
		}
		return !Objects.equals(newObject.getCanonicalPath(), oldObject.getCanonicalPath());
	}

	/**
	 * Determine whether two values differ
	 * 
	 * <p>
	 * By default this defers to the values' Object{@link #equals(Object)} methods, or in case both
	 * are of type {@link TraceObject}, to {@link #isObjectsDiffer(TraceObject, TraceObject)}. This
	 * method should only be called for values at the same path.
	 * 
	 * @param newValue the current value
	 * @param oldValue the previous value
	 * @return true if the values differ, i.e., should be displayed in red
	 */
	default boolean isValuesDiffer(Object newValue, Object oldValue) {
		if (newValue instanceof TraceObject && oldValue instanceof TraceObject) {
			return isObjectsDiffer((TraceObject) newValue, (TraceObject) oldValue);
		}
		return !Objects.equals(newValue, oldValue);
	}

	/**
	 * Determine whether two object values (edges) differ
	 * 
	 * <p>
	 * By default, this behaves as in {@link Objects#equals(Object)}, deferring to
	 * {@link #isValuesDiffer(Object, Object)}. Note that newEdge can be null because span may
	 * include more than the current snap. It will be null for edges that are displayed but do not
	 * contains the current snap.
	 * 
	 * @param newEdge the current edge, possibly null
	 * @param oldEdge the previous edge, possibly null
	 * @return true if the edges' values differ
	 */
	default boolean isEdgesDiffer(TraceObjectValue newEdge, TraceObjectValue oldEdge) {
		if (newEdge == oldEdge) { // Covers case where both are null
			return false;
		}
		if (newEdge == null || oldEdge == null) {
			return true;
		}
		return isValuesDiffer(newEdge.getValue(), oldEdge.getValue());
	}

	default boolean isValueModified(TraceObjectValue value) {
		if (value == null || value.getParent() == null) {
			return false;
		}
		Trace diffTrace = getDiffTrace();
		if (diffTrace == null) {
			return false;
		}
		Trace trace = getTrace();
		long snap = getSnap();
		long diffSnap = getDiffSnap();
		if (diffTrace == trace && diffSnap == snap) {
			return false;
		}
		if (diffTrace == trace) {
			boolean newContains = value.getLifespan().contains(snap);
			boolean oldContains = value.getLifespan().contains(diffSnap);
			if (newContains == oldContains) {
				return newContains ? isEdgesDiffer(value, value) : true;
			}
			TraceObjectValue diffEdge = value.getParent().getValue(diffSnap, value.getEntryKey());
			return isEdgesDiffer(newContains ? value : null, diffEdge);
		}
		TraceObjectValue diffEdge = diffTrace.getObjectManager()
				.getValuePaths(Range.singleton(diffSnap),
					PathPredicates.pattern(value.getCanonicalPath().getKeyList()))
				.findAny()
				.map(p -> p.getLastEntry())
				.orElse(null);
		return isEdgesDiffer(value, diffEdge);
	}
}
