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

import ghidra.pcode.emu.DefaultPcodeThread.PcodeEmulationLibrary;
import ghidra.pcode.exec.SleighUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.*;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.DuplicateNameException;

/**
 * A breakpoint in a trace
 */
public interface TraceBreakpoint extends TraceUniqueObject {
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
	 * @param name the new name
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
	 * Get the minimum address in this breakpoint's range
	 * 
	 * @see #getRange()
	 * @return the minimum address
	 */
	Address getMinAddress();

	/**
	 * Get the maximum address in this breakpoint's range
	 * 
	 * @see #getRange()
	 * @return the maximum address
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
	 * @deprecated Either this method no longer makes sense, or we need to wrap a
	 *             {@link TraceObjectValue} instead. Even then, the attribute values can vary over
	 *             the lifespan.
	 */
	@Deprecated(since = "11.3", forRemoval = true)
	Lifespan getLifespan();

	/**
	 * Check if the breakpoint is present at the given snap
	 * 
	 * @param snap the snap
	 * @return true if alive, false if not
	 */
	boolean isAlive(long snap);

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
	 * @throws DuplicateNameException if extending the lifespan would cause a naming collision
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
	 * Check whether this breakpoint is enabled or disabled at the given snap
	 * 
	 * @param snap the snap
	 * @return true if enabled, false if disabled
	 */
	boolean isEnabled(long snap);

	/**
	 * Set whether this breakpoint is enabled or disabled for emulation
	 * 
	 * <p>
	 * This change applies to the entire lifespan of the record. It's not intended to record a
	 * history, but to toggle the breakpoint in the integrated emulator.
	 * 
	 * @param enabled true if enabled, false if disabled
	 */
	void setEmuEnabled(boolean enabled);

	/**
	 * Check whether this breakpoint is enabled or disabled for emulation at the given snap
	 * 
	 * @param snap the snap
	 * @return true if enabled, false if disabled
	 */
	boolean isEmuEnabled(long snap);

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
	 * Set Sleigh source to replace the breakpointed instruction in emulation
	 * 
	 * <p>
	 * The default is simply:
	 * </p>
	 * 
	 * <pre>
	 * {@link PcodeEmulationLibrary#emu_swi() emu_swi()};
	 * {@link PcodeEmulationLibrary#emu_exec_decoded() emu_exec_decoded()};
	 * </pre>
	 * <p>
	 * That is effectively a non-conditional breakpoint followed by execution of the actual
	 * instruction. Modifying this allows clients to create conditional breakpoints or simply
	 * override or inject additional logic into an emulated target.
	 * 
	 * <p>
	 * <b>NOTE:</b> This currently has no effect on access breakpoints, but only execution
	 * breakpoints.
	 * 
	 * <p>
	 * If the specified source fails to compile during emulator set-up, this will fall back to
	 * {@link PcodeEmulationLibrary#emu_swi()}
	 * 
	 * @see SleighUtils#UNCONDITIONAL_BREAK
	 * @param sleigh the Sleigh source
	 */
	void setEmuSleigh(String sleigh);

	/**
	 * Get the Sleigh source that replaces the breakpointed instruction in emulation
	 * 
	 * @return the Sleigh source
	 */
	String getEmuSleigh();

	/**
	 * Delete this breakpoint from the trace
	 */
	void delete();

	/**
	 * Check if the breakpoint is valid at the given snapshot
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
}
