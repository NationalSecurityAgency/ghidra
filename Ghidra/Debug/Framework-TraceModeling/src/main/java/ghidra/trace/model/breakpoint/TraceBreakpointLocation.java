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

import java.util.Set;

import ghidra.pcode.emu.DefaultPcodeThread.PcodeEmulationLibrary;
import ghidra.pcode.exec.SleighUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.info.TraceObjectInfo;
import ghidra.trace.model.thread.TraceThread;

@TraceObjectInfo(
	schemaName = "BreakpointLocation",
	shortName = "breakpoint location",
	attributes = {
		TraceBreakpointLocation.KEY_RANGE,
		TraceBreakpointLocation.KEY_EMU_ENABLED,
		TraceBreakpointLocation.KEY_EMU_SLEIGH,
	},
	fixedKeys = {
		TraceBreakpointLocation.KEY_RANGE,
	})
public interface TraceBreakpointLocation extends TraceBreakpointCommon {
	String KEY_RANGE = "_range";
	String KEY_EMU_ENABLED = "_emu_enabled";
	String KEY_EMU_SLEIGH = "_emu_sleigh";

	/**
	 * Get the specification that caused this location to exist
	 * 
	 * @return the specification
	 */
	TraceBreakpointSpec getSpecification();

	/**
	 * See {@link TraceBreakpointSpec#getKinds(long)}
	 * 
	 * @param snap the snap
	 * @return the kinds
	 */
	default Set<TraceBreakpointKind> getKinds(long snap) {
		return getSpecification().getKinds(snap);
	}

	/**
	 * Get the set of threads to which this breakpoint's application is limited
	 * 
	 * <p>
	 * Note, an empty set here implies all contemporary live threads, i.e., the process.
	 * 
	 * @param snap the snap
	 * @return the (possibly empty) set of affected threads
	 */
	@Deprecated(forRemoval = true, since = "12.0")
	Set<TraceThread> getThreads(long snap);

	/**
	 * Set the range covered by this breakpoint location
	 * 
	 * @param lifespan the span of time
	 * @param range the span of addresses
	 */
	void setRange(Lifespan lifespan, AddressRange range);

	/**
	 * Get the range covered by this breakpoint location
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
	 * Set whether this breakpoint is enabled or disabled for emulation
	 * 
	 * @param lifespan the span of time
	 * @param enabled true if enabled, false if disabled
	 */
	void setEmuEnabled(Lifespan lifespan, boolean enabled);

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
	 * As in {@link #setEmuSleigh(long, String)}, but for a specific lifespan
	 * 
	 * @param lifespan the span of time
	 * @param sleigh the Sleigh source
	 */
	void setEmuSleigh(Lifespan lifespan, String sleigh);

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
}
