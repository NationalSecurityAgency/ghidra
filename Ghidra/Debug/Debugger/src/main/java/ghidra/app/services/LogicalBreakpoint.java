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
package ghidra.app.services;

import java.util.Collection;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;

public interface LogicalBreakpoint {
	String BREAKPOINT_ENABLED_BOOKMARK_TYPE = "BreakpointEnabled";
	String BREAKPOINT_DISABLED_BOOKMARK_TYPE = "BreakpointDisabled";

	public enum Enablement {
		NONE(false, false, true) {
			@Override
			public Enablement getPrimary() {
				return NONE;
			}
		},
		ENABLED(true, false, true) {
			@Override
			public Enablement getPrimary() {
				return ENABLED;
			}
		},
		DISABLED(false, true, true) {
			@Override
			public Enablement getPrimary() {
				return DISABLED;
			}
		},
		ENABLED_DISABLED(true, false, false) {
			@Override
			public Enablement getPrimary() {
				return ENABLED;
			}
		},
		DISABLED_ENABLED(false, true, false) {
			@Override
			public Enablement getPrimary() {
				return DISABLED;
			}
		};

		public final boolean enabled;
		public final boolean disabled;
		public final boolean consistent;

		Enablement(boolean enabled, boolean disabled, boolean consistent) {
			this.enabled = enabled;
			this.disabled = disabled;
			this.consistent = consistent;
		}

		public Enablement combine(Enablement that) {
			if (this == NONE) {
				return that;
			}
			if (that == NONE) {
				return this;
			}
			return fromBools(this.enabled, that.enabled);
		}

		public Enablement sameAdddress(Enablement that) {
			if (this == NONE) {
				return that;
			}
			if (that == NONE) {
				return this;
			}
			return fromBools(this.enabled || that.enabled, this.enabled && that.enabled);
		}

		public static Enablement sameAddress(Collection<Enablement> col) {
			Enablement result = NONE;
			for (Enablement e : col) {
				result = result.sameAdddress(e);
			}
			return result;
		}

		public static Enablement fromBools(boolean firstEn, boolean secondEn) {
			if (firstEn) {
				if (secondEn) {
					return ENABLED;
				}
				else {
					return ENABLED_DISABLED;
				}
			}
			else {
				if (secondEn) {
					return DISABLED_ENABLED;
				}
				else {
					return DISABLED;
				}
			}
		}

		public abstract Enablement getPrimary();
	}

	/**
	 * True if there is neither a program bookmark nor any trace breakpoints aggregated.
	 * 
	 * @return true if empty
	 */
	boolean isEmpty();

	/**
	 * Get the kinds of this logical breakpoint.
	 * 
	 * @return the kinds
	 */
	Set<TraceBreakpointKind> getKinds();

	/**
	 * If the logical breakpoint has a mapped program location, get that program.
	 * 
	 * @return the program if mapped, or {@code null}
	 */
	default Program getProgram() {
		ProgramLocation loc = getProgramLocation();
		return loc == null ? null : loc.getProgram();
	}

	/**
	 * If the logical breakpoint is present in a program, get its bookmark.
	 * 
	 * Note it is possible for a logical breakpoint to have a mapped program location, even though
	 * that location is not bookmarked, i.e., the breakpoint may not be present in the program.
	 * 
	 * @return the bookmark, or {@code null}
	 */
	Bookmark getProgramBookmark();

	/**
	 * If the logical breakpoint has a mapped program location, get that location.
	 * 
	 * @return the location if mapped, or {@code null}
	 */
	ProgramLocation getProgramLocation();

	/**
	 * Get the (requested) length of this breakpoint
	 * 
	 * Each debugger may choose whether or not to heed this, and it may depend on the breakpoint
	 * kinds. To know the actual length given by the debugger, inspect each contained breakpoint
	 * individually.
	 * 
	 * @return the requested length
	 */
	long getLength();

	/**
	 * Get all trace breakpoints which map to this logical breakpoint.
	 * 
	 * Note that not all traces for which this logical breakpoint has an address will have a
	 * corresponding trace breakpoint, i.e., the breakpoint may not be present in every mappable
	 * trace.
	 * 
	 * @return the set of trace breakpoints
	 */
	Set<TraceBreakpoint> getTraceBreakpoints();

	/**
	 * Get all trace breakpoints for the given trace which map to this logical breakpoint.
	 * 
	 * @param trace the trace
	 * @return the set of trace breakpoints
	 */
	Set<TraceBreakpoint> getTraceBreakpoints(Trace trace);

	/**
	 * Get the traces for which this logical breakpoint has an address.
	 * 
	 * Note, this does not necessarily indicate that a {@link TraceBreakpoint} is present for each
	 * trace, but rather that for each returned trace, the logical breakpoint can be mapped to an
	 * address in that trace. See {@link #getParticipatingTraces()}.
	 * 
	 * @return the set of traces
	 */
	Set<Trace> getMappedTraces();

	/**
	 * Get the traces for which this logical breakpoint has a trace breakpoint.
	 * 
	 * Note, unlike {@link #getMappedTraces()}, this does indicate that a {@link TraceBreakpoint} is
	 * present for each trace.
	 * 
	 * @return the set of traces
	 */
	Set<Trace> getParticipatingTraces();

	/**
	 * If the logical breakpoint has a mapped location for the given trace, get the address.
	 * 
	 * @param trace the desired trace
	 * @return the address if mapped, or {@code null}.
	 */
	Address getTraceAddress(Trace trace);

	/**
	 * Get the best representative domain object for this breakpoint's location
	 * 
	 * @return the domain object (program or trace)
	 */
	DomainObject getDomainObject();

	/**
	 * Get the address within the domain object that best locates this breakpoint
	 * 
	 * @return the address
	 */
	Address getAddress();

	/**
	 * Compute the enablement status for the given program.
	 * 
	 * @param program the program
	 * @return the enablement
	 */
	Enablement computeEnablementForProgram(Program program);

	/**
	 * Compute the enablement status for the given trace.
	 * 
	 * @param trace the trace
	 * @return the enablement
	 */
	Enablement computeEnablementForTrace(Trace trace);

	/**
	 * Compute the enablement status for all involved traces and program.
	 * 
	 * @return the enablement
	 */
	Enablement computeEnablement();

	/**
	 * Place an "enabled breakpoint" bookmark in the mapped program, if applicable.
	 */
	void enableForProgram();

	/**
	 * Place a "disabled breakpoint" bookmark in the mapped program, if applicable.
	 */
	void disableForProgram();

	/**
	 * Delete any "breakpoint" bookmark in the mapped program, if applicable.
	 */
	void deleteForProgram();

	/**
	 * Enable (or create) this breakpoint in the given target.
	 * 
	 * Presuming the breakpoint is mappable to the given trace, if no breakpoint of the same kind
	 * exists at the mapped address, then this will create a new breakpoint. Note, depending on the
	 * debugging model, the enabled or created breakpoint may apply to more than the given trace.
	 * 
	 * This simply issues the command. The logical breakpoint is updated only when the resulting
	 * events are processed.
	 * 
	 * @param trace the trace for the given target
	 * @return a future which completes when the breakpoint is enabled
	 */
	CompletableFuture<Void> enableForTrace(Trace trace);

	/**
	 * Disable this breakpoint in the given target.
	 * 
	 * Note this will not create any new breakpoints. It will disable all breakpoints of the same
	 * kind at the mapped address. Note, depending on the debugging model, the disabled breakpoint
	 * may apply to more than the given trace.
	 * 
	 * This simply issues the command. The logical breakpoint is updated only when the resulting
	 * events are processed.
	 * 
	 * @param trace the trace for the given target
	 * @return a future which completes when the breakpoint is disabled
	 */
	CompletableFuture<Void> disableForTrace(Trace trace);

	/**
	 * Delete this breakpoint in the given target.
	 * 
	 * This presumes the breakpoint's specifications are deletable. Note that if the logical
	 * breakpoint is still mappable into this trace, a marker may be displayed, even though no
	 * breakpoint is actually present. Note, depending on the debugging model, the deleted
	 * breakpoint may be removed from more than the given trace.
	 * 
	 * This simply issues the command. The logical breakpoint is updated only when the resulting
	 * events are processed.
	 * 
	 * @param trace the trace for the given target
	 * @return a future which completes when the breakpoint is deleted
	 */
	CompletableFuture<Void> deleteForTrace(Trace trace);

	/**
	 * Enable (or create) this breakpoint everywhere in the tool.
	 * 
	 * This affects the mapped program, if applicable, and all open and live traces. Note, depending
	 * on the debugging model, the enabled or created breakpoints may apply to more targets.
	 * 
	 * This simply issues the command. The logical breakpoint is updated only when the resulting
	 * events are processed.
	 * 
	 * @return a future which completes when the breakpoint is enabled
	 */
	CompletableFuture<Void> enable();

	/**
	 * Disable this breakpoint everywhere in the tool.
	 * 
	 * This affects the mapped program, if applicable, and all open and live traces. Note, depending
	 * on the debugging model, the disabled breakpoints may apply to more targets.
	 * 
	 * This simply issues the command. The logical breakpoint is updated only when the resulting
	 * events are processed.
	 * 
	 * @return a future which completes when the breakpoint is disabled
	 */
	CompletableFuture<Void> disable();

	/**
	 * Delete this breakpoint everywhere in the tool.
	 * 
	 * This presumes the breakpoint's specifications are deletable. This affects the mapped program,
	 * if applicable, and all open and live traces. Note, depending on the debugging model, the
	 * deleted breakpoints may be removed from more targets.
	 * 
	 * This simply issues the command. The logical breakpoint is updated only when the resulting
	 * events are processed.
	 * 
	 * @return a future which completes when the breakpoint is deleted
	 */
	CompletableFuture<Void> delete();
}
