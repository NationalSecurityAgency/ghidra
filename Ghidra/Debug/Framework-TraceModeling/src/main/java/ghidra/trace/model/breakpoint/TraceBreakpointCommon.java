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
package ghidra.trace.model.breakpoint;

import ghidra.trace.model.*;
import ghidra.trace.model.target.iface.TraceObjectInterface;

public interface TraceBreakpointCommon extends TraceUniqueObject, TraceObjectInterface {
	// LATER?: Hit count

	/**
	 * Get the trace containing this breakpoint
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the "full name" of this breakpoint
	 * 
	 * <p>
	 * This is a name unique to this breakpoint, which may not be suitable for display on the
	 * screen.
	 * 
	 * @return the path
	 */
	String getPath();

	/**
	 * Set the "short name" of this breakpoint
	 * 
	 * <p>
	 * This should be a name suitable for display on the screen
	 * 
	 * @param lifespan the span of time
	 * @param name the new name
	 */
	void setName(Lifespan lifespan, String name);

	/**
	 * Set the "short name" of this breakpoint
	 * 
	 * <p>
	 * This should be a name suitable for display on the screen
	 * 
	 * @param snap the first effective snap
	 * @param name the new name
	 */
	void setName(long snap, String name);

	/**
	 * Get the "short name" of this breakpoint
	 * 
	 * <p>
	 * This defaults to the "full name," but can be modified via {@link #setName(long, String)}
	 * 
	 * @param snap the snap
	 * @return the name
	 */
	String getName(long snap);

	/**
	 * Set whether this breakpoint was enabled or disabled
	 * 
	 * @param lifespan the span of time
	 * @param enabled true if enabled, false if disabled
	 */
	void setEnabled(Lifespan lifespan, boolean enabled);

	/**
	 * Set whether this breakpoint was enabled or disabled
	 * 
	 * @param snap the first effective snap
	 * @param enabled true if enabled, false if disabled
	 */
	void setEnabled(long snap, boolean enabled);

	/**
	 * Check whether this breakpoint is enabled or disabled at the given snap
	 * 
	 * @param snap the snap
	 * @return true if enabled, false if disabled
	 */
	boolean isEnabled(long snap);

	/**
	 * Set a comment on this breakpoint
	 * 
	 * @param lifespan the span of time
	 * @param comment the comment, possibly {@code null}
	 */
	void setComment(Lifespan lifespan, String comment);

	/**
	 * Set a comment on this breakpoint
	 * 
	 * @param snap the snap
	 * @param comment the comment, possibly {@code null}
	 */
	void setComment(long snap, String comment);

	/**
	 * Get the comment on this breakpoint
	 * 
	 * @param snap the snap
	 * @return the comment, possibly {@code null}
	 */
	String getComment(long snap);

	/**
	 * Remove this breakpoint from the given snap on
	 * 
	 * @param snap the snap
	 */
	void remove(long snap);

	/**
	 * Delete this breakpoint from the trace
	 */
	void delete();

	/**
	 * Check if the breakpoint is present at the given snapshot
	 * 
	 * <p>
	 * In object mode, a breakpoint's life may be disjoint, so checking if the snap occurs between
	 * creation and destruction is not quite sufficient. This method encapsulates validity. In
	 * object mode, it checks that the breakpoint object has a canonical parent at the given
	 * snapshot. In table mode, it checks that the lifespan contains the snap.
	 * 
	 * @param snap the snapshot key
	 * @return true if valid, false if not
	 */
	boolean isValid(long snap);

	/**
	 * Check if the breakpoint is present for any of the given span
	 * 
	 * @param span the span
	 * @return true if its life intersects the span
	 */
	boolean isAlive(Lifespan span);
}
