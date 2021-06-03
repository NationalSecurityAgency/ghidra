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

import java.util.Collection;
import java.util.Set;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceObject;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.DuplicateNameException;

/**
 * A breakpoint in a trace
 */
public interface TraceBreakpoint extends TraceObject {

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
	 */
	void setName(String name);

	/**
	 * Get the "short name" of this breakpoint
	 * 
	 * <p>
	 * This defaults to the "full name," but can be modified via {@link #setName(String)}
	 * 
	 * @return the name
	 */
	String getName();

	/**
	 * Get the range covered by this breakpoint
	 * 
	 * <p>
	 * Most often, esp. for execution breakpoints, this is a single address.
	 * 
	 * @return the range
	 */
	AddressRange getRange();

	/**
	 * @see #getRange()
	 */
	Address getMinAddress();

	/**
	 * @see #getRange()
	 */
	Address getMaxAddress();

	/**
	 * Get the length of this breakpoint, usually 1
	 * 
	 * @return the length
	 */
	long getLength();

	/**
	 * Get the lifespan of this breakpoint
	 * 
	 * @return the lifespan
	 */
	Range<Long> getLifespan();

	/**
	 * Get the placed snap of this breakpoint
	 * 
	 * @return the placed snap, or {@link Long#MIN_VALUE} for "since the beginning of time"
	 */
	long getPlacedSnap();

	/**
	 * Set the cleared snap of this breakpoint
	 * 
	 * @param clearedSnap the cleared snap, or {@link Long#MAX_VALUE} for "to the end of time"
	 */
	void setClearedSnap(long clearedSnap) throws DuplicateNameException;

	/**
	 * Get the cleared snap of this breakpoint
	 * 
	 * @return the cleared snap, or {@link Long#MAX_VALUE} for "to the end of time"
	 */
	long getClearedSnap();

	/**
	 * Split this breakpoint at the given snap, and set the later's fields.
	 * 
	 * <p>
	 * This breakpoint's lifespan must contain the given snap. This method first creates a copy of
	 * this breakpoint, replacing the copy's placed snap and additional fields. Then, it sets this
	 * breakpoint's cleared snap to one less than the given snap, so that the two breakpoints do not
	 * overlap.
	 * 
	 * <p>
	 * Note the following special cases: 1) If the given snap is equal to the placed snap, this
	 * method simply sets the fields on this breakpoint and returns this. 2) If the field values
	 * indicate no change, this method does nothing and returns this breakpoint.
	 * 
	 * @implNote Listeners on breakpoint changes will see the added record before the lifespan
	 *           change of the old record, despite those two records having the same path and
	 *           overlapping in time. This makes it easier for such listeners to distinguish such
	 *           splits from a breakpoint being cleared.
	 * 
	 * @param snap the placed snap for the later breakpoint
	 * @param enabled true if the later breakpoint is enabled, false if disabled
	 * @param kinds the kinds of the later breakpoint
	 * @return the new breakpoint, or this breakpoint (see special case)
	 */
	TraceBreakpoint splitAndSet(long snap, boolean enabled, Collection<TraceBreakpointKind> kinds);

	/**
	 * Set whether this breakpoint was enabled or disabled
	 * 
	 * <p>
	 * This change applies to the entire lifespan of this record. If a breakpoint is enabled for
	 * some duration and then later disabled, this breakpoint should be split instead. See
	 * {@link #splitAndSet(long,boolean, Collection)}.
	 * 
	 * @param enabled true if enabled, false if disabled
	 */
	void setEnabled(boolean enabled);

	/**
	 * Check whether this breakpoint is enabled or disabled
	 * 
	 * @return true if enabled, false if disabled
	 */
	boolean isEnabled();

	/**
	 * Set the kinds included in this breakpoint
	 * 
	 * <p>
	 * See {@link #getKinds()}. Note that it is unusual for a breakpoint to change kinds during its
	 * life. Nevertheless, in the course of recording a trace, it may happen, or at least appear to
	 * happen. Rather than require the client to delete and re-create the breakpoint, this allows
	 * the record to be updated. See also {@link #splitAndSet(long, boolean, Collection)}.
	 * 
	 * @param kinds the set of kinds
	 */
	void setKinds(Collection<TraceBreakpointKind> kinds);

	/**
	 * Get the kinds included in this breakpoint
	 * 
	 * <p>
	 * For example, an "access breakpoint" or "access watchpoint," depending on terminology, would
	 * include both {@link TraceBreakpointKind#READ} and {@link TraceBreakpointKind#WRITE}.
	 * 
	 * @return the set of kinds
	 */
	Set<TraceBreakpointKind> getKinds();

	/**
	 * Get the set of threads to which this breakpoint's application is limited
	 * 
	 * <p>
	 * Note, an empty set here implies all contemporary live threads, i.e., the process.
	 * 
	 * @return the (possibly empty) set of affected threads
	 */
	Set<TraceThread> getThreads();

	/**
	 * Set a comment on this breakpoint
	 * 
	 * @param comment the comment, possibly {@code null}
	 */
	void setComment(String comment);

	/**
	 * Get the comment on this breakpoint
	 * 
	 * @return the comment, possibly {@code null}
	 */
	String getComment();

	/**
	 * Delete this breakpoint from the trace
	 */
	void delete();
}
