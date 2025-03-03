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
import ghidra.trace.model.thread.TraceThread;

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
	 * Get the range covered by this breakpoint
	 * 
	 * <p>
	 * Most often, esp. for execution breakpoints, this is a single address.
	 * 
	 * @param snap the snap
	 * @return the range
	 */
	AddressRange getRange(long snap);

	/**
	 * Get the minimum address in this breakpoint's range
	 * 
	 * @see #getRange(long)
	 * @param snap the snap
	 * @return the minimum address
	 */
	Address getMinAddress(long snap);

	/**
	 * Get the maximum address in this breakpoint's range
	 * 
	 * @see #getRange(long)
	 * @param snap the snap
	 * @return the maximum address
	 */
	Address getMaxAddress(long snap);

	/**
	 * Get the length of this breakpoint, usually 1
	 * 
	 * @param snap the snap
	 * @return the length
	 */
	long getLength(long snap);

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
	 * Set whether this breakpoint is enabled or disabled for emulation
	 * 
	 * @param snap the snap
	 * @param enabled true if enabled, false if disabled
	 */
	void setEmuEnabled(long snap, boolean enabled);

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
	 * See {@link #getKinds(long)}. Note that it is unusual for a breakpoint to change kinds during
	 * its life. Nevertheless, in the course of recording a trace, it may happen, or at least appear
	 * to happen.
	 * 
	 * @param snap the snap
	 * @param kinds the set of kinds
	 */
	void setKinds(long snap, Collection<TraceBreakpointKind> kinds);

	/**
	 * Get the kinds included in this breakpoint
	 * 
	 * <p>
	 * For example, an "access breakpoint" or "access watchpoint," depending on terminology, would
	 * include both {@link TraceBreakpointKind#READ} and {@link TraceBreakpointKind#WRITE}.
	 * 
	 * @param snap the snap
	 * @return the set of kinds
	 */
	Set<TraceBreakpointKind> getKinds(long snap);

	/**
	 * Get the set of threads to which this breakpoint's application is limited
	 * 
	 * <p>
	 * Note, an empty set here implies all contemporary live threads, i.e., the process.
	 * 
	 * @param snap the snap
	 * @return the (possibly empty) set of affected threads
	 */
	Set<TraceThread> getThreads(long snap);

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
	 * @param snap the snap
	 * @param sleigh the Sleigh source
	 */
	void setEmuSleigh(long snap, String sleigh);

	/**
	 * Get the Sleigh source that replaces the breakpointed instruction in emulation
	 * 
	 * @param snap the snap
	 * @return the Sleigh source
	 */
	String getEmuSleigh(long snap);

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
