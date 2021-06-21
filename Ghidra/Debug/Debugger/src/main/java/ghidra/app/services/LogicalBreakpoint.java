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

	/**
	 * The state of a logical breakpoint's program bookmark
	 */
	public enum ProgramEnablement {
		/**
		 * A placeholder state when the program bookmark state is not applicable
		 */
		NONE {
			@Override
			public Enablement combineTrace(TraceEnablement traceEn) {
				switch (traceEn) {
					case NONE:
						return Enablement.NONE;
					case MISSING:
						return Enablement.NONE;
					case ENABLED:
						return Enablement.ENABLED;
					case MIXED:
						return Enablement.DISABLED_ENABLED;
					case DISABLED:
						return Enablement.DISABLED;
					default:
						throw new AssertionError();
				}
			}
		},
		/**
		 * The state when the program location applies, but no breakpoint is present there
		 * 
		 * <p>
		 * This can happen when a breakpoint is placed directly in the debugger at a mapped address,
		 * but that breakpoint is not (yet) bookmarked in the mapped program.
		 */
		MISSING {
			@Override
			public Enablement combineTrace(TraceEnablement traceEn) {
				switch (traceEn) {
					case NONE:
						return Enablement.NONE;
					case MISSING:
						return Enablement.NONE;
					case ENABLED:
					case MIXED:
						return Enablement.DISABLED_ENABLED;
					case DISABLED:
						return Enablement.DISABLED;
					default:
						throw new AssertionError();
				}
			}
		},
		/**
		 * The breakpoint's program bookmark is enabled
		 */
		ENABLED {
			@Override
			public Enablement combineTrace(TraceEnablement traceEn) {
				switch (traceEn) {
					case NONE:
					case MISSING:
						return Enablement.INEFFECTIVE_ENABLED;
					case ENABLED:
						return Enablement.ENABLED;
					case DISABLED:
					case MIXED:
						return Enablement.ENABLED_DISABLED;
					default:
						throw new AssertionError();
				}
			}
		},
		/**
		 * The breakpoint's program bookmark is disabled
		 */
		DISABLED {
			@Override
			public Enablement combineTrace(TraceEnablement traceEn) {
				switch (traceEn) {
					case NONE:
					case MISSING:
						return Enablement.INEFFECTIVE_DISABLED;
					case ENABLED:
					case MIXED:
						return Enablement.DISABLED_ENABLED;
					case DISABLED:
						return Enablement.DISABLED;
					default:
						throw new AssertionError();
				}
			}
		};

		/**
		 * Compose the logical breakpoint state from the perspective of the program, given the
		 * composed state of its locations
		 * 
		 * <p>
		 * This state is generally considered the state of the logical breakpoint. In other words,
		 * the program's perspective is the default.
		 * 
		 * @param traceEn the state of its locations
		 * @return the logical state
		 */
		public abstract Enablement combineTrace(TraceEnablement traceEn);
	}

	/**
	 * The state of a logical breakpoint's trace/target locations
	 */
	public enum TraceEnablement {
		/**
		 * A placeholder state when the breakpoint is not mapped to any trace
		 */
		NONE {
			@Override
			public TraceEnablement combine(TraceEnablement that) {
				return that;
			}

			@Override
			public Enablement combineProgram(ProgramEnablement progEn) {
				switch (progEn) {
					case NONE:
					case MISSING:
						return Enablement.NONE;
					case ENABLED:
						return Enablement.INEFFECTIVE_ENABLED;
					case DISABLED:
						return Enablement.INEFFECTIVE_DISABLED;
					default:
						throw new AssertionError();
				}
			}
		},
		/**
		 * The state when the breakpoint is mapped to at least one trace, but no locations are
		 * placed
		 */
		MISSING {
			@Override
			public TraceEnablement combine(TraceEnablement that) {
				return that;
			}

			@Override
			public Enablement combineProgram(ProgramEnablement progEn) {
				switch (progEn) {
					case NONE:
					case MISSING:
						return Enablement.NONE;
					case ENABLED:
						return Enablement.INEFFECTIVE_ENABLED;
					case DISABLED:
						return Enablement.INEFFECTIVE_DISABLED;
					default:
						throw new AssertionError();
				}
			}
		},
		/**
		 * The state when all mapped locations are placed and enabled
		 */
		ENABLED {
			@Override
			public TraceEnablement combine(TraceEnablement that) {
				switch (that) {
					case NONE:
					case MISSING:
					case ENABLED:
						return ENABLED;
					case DISABLED:
					case MIXED:
						return MIXED;
					default:
						throw new AssertionError();
				}
			}

			@Override
			public Enablement combineProgram(ProgramEnablement progEn) {
				switch (progEn) {
					case NONE:
					case MISSING:
					case DISABLED:
						return Enablement.ENABLED_DISABLED;
					case ENABLED:
						return Enablement.ENABLED;
					default:
						throw new AssertionError();
				}
			}
		},
		/**
		 * The state when all mapped locations are placed and disabled
		 */
		DISABLED {
			@Override
			public TraceEnablement combine(TraceEnablement that) {
				switch (that) {
					case NONE:
					case MISSING:
					case DISABLED:
						return DISABLED;
					case ENABLED:
					case MIXED:
						return MIXED;
					default:
						throw new AssertionError();
				}
			}

			@Override
			public Enablement combineProgram(ProgramEnablement progEn) {
				switch (progEn) {
					case NONE:
					case MISSING:
					case DISABLED:
						return Enablement.DISABLED;
					case ENABLED:
						return Enablement.DISABLED_ENABLED;
					default:
						throw new AssertionError();
				}
			}
		},
		/**
		 * The state when some mapped locations are enabled and some are disabled
		 */
		MIXED {
			@Override
			public TraceEnablement combine(TraceEnablement that) {
				return MIXED;
			}

			@Override
			public Enablement combineProgram(ProgramEnablement progEn) {
				return Enablement.ENABLED_DISABLED;
			}
		};

		/**
		 * Convert a boolean to trace enablement
		 * 
		 * @param en true for {@link #ENABLED}, false for {@link #DISABLED}
		 * @return the state
		 */
		public static TraceEnablement fromBool(boolean en) {
			return en ? ENABLED : DISABLED;
		}

		/**
		 * For locations of the same logical breakpoint, compose the state
		 * 
		 * @param that the other state
		 * @return the composed state
		 */
		public abstract TraceEnablement combine(TraceEnablement that);

		/**
		 * Compose the logical breakpoint state from the perspective of the trace, given the state
		 * of its program bookmark.
		 * 
		 * <p>
		 * Typically, this is used not on a composed trace state, but on the one trace whose
		 * perspective to consider. This should only be used when choosing how to render a
		 * breakpoint in that trace's listing.
		 * 
		 * @param progEn the state of the program bookmark
		 * @return the per-trace logical state
		 */
		public abstract Enablement combineProgram(ProgramEnablement progEn);
	}

	/**
	 * The state of a logical breakpoint, i.e., whether or not its parts are enabled
	 */
	public enum Enablement {
		/**
		 * A placeholder state, usually indicating the logical breakpoint should not exist
		 * 
		 * <p>
		 * This state should not ever be assigned to any actual breakpoint, except if that
		 * breakpoint is ephemeral and about to be removed. This value may appear during
		 * computations and is a suitable default placeholder for editors and renderers.
		 */
		NONE(false, false, true, false) {
			@Override
			public Enablement getPrimary() {
				return NONE;
			}
		},
		/**
		 * The breakpoint's bookmark and all mapped locations are placed and enabled
		 */
		ENABLED(true, false, true, true) {
			@Override
			public Enablement getPrimary() {
				return ENABLED;
			}
		},
		/**
		 * The breakpoint's bookmark and all mapped locations are placed and disabled
		 */
		DISABLED(false, true, true, true) {
			@Override
			public Enablement getPrimary() {
				return DISABLED;
			}
		},
		/**
		 * The breakpoint's bookmark is enabled, but it has no mapped locations placed
		 */
		INEFFECTIVE_ENABLED(true, false, true, false) {
			@Override
			public Enablement getPrimary() {
				return ENABLED;
			}
		},
		/**
		 * The breakpoint's bookmark is disabled, and it has no mapped locations placed
		 */
		INEFFECTIVE_DISABLED(false, true, true, false) {
			@Override
			public Enablement getPrimary() {
				return DISABLED;
			}
		},
		/**
		 * The breakpoint's bookmark is enabled, but at least one mapped location is disabled
		 */
		ENABLED_DISABLED(true, false, false, true) {
			@Override
			public Enablement getPrimary() {
				return ENABLED;
			}
		},
		/**
		 * The breakpoint's bookmark is disabled, but at least one mapped location is enabled
		 */
		DISABLED_ENABLED(false, true, false, true) {
			@Override
			public Enablement getPrimary() {
				return DISABLED;
			}
		};

		public final boolean enabled; // indicates any enabled location
		public final boolean disabled; // indicates any disabled location
		public final boolean consistent; // bookmark and target locations all agree
		public final boolean effective; // has a target location, even if disabled

		Enablement(boolean enabled, boolean disabled, boolean consistent, boolean effective) {
			this.enabled = enabled;
			this.disabled = disabled;
			this.consistent = consistent;
			this.effective = effective;
		}

		/**
		 * For logical breakpoints which appear at the same address, compose their state
		 * 
		 * <p>
		 * This can happen when two logical breakpoints, having different attributes (size, kinds,
		 * etc.) coincide at the same address. This should be used only when deciding how to mark or
		 * choose actions for the address.
		 * 
		 * @param that the other state.
		 * @return the composed state
		 */
		public Enablement sameAdddress(Enablement that) {
			if (this == NONE) {
				return that;
			}
			if (that == NONE) {
				return this;
			}
			if (!this.effective && !that.effective) {
				return this.enabled || that.enabled ? INEFFECTIVE_ENABLED : INEFFECTIVE_DISABLED;
			}
			return fromBools(this.enabled || that.enabled, this.enabled && that.enabled);
		}

		/**
		 * For logical breakpoints which appear at the same address, compose their state
		 * 
		 * @see #sameAdddress(Enablement)
		 * @param col a collection of states derived from logical breakpoints at the same address
		 * @return the composed state
		 */
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

		/**
		 * Get the "primary" state represented by this logical state
		 * 
		 * <p>
		 * Generally, this is the state of the bookmark, i.e., program breakpoint. Not all logical
		 * breakpoints have a placed bookmark, though. In that case, this still returns a reasonable
		 * "primary" state.
		 * 
		 * @return the state
		 */
		public abstract Enablement getPrimary();

		/**
		 * Get the desired state were the the logical breakpoint to be toggled
		 * 
		 * <p>
		 * The expected "action" when toggling a breakpoint may vary depending on whether or not the
		 * breakpoint is mapped, and the notion of "mapped" may vary depending on other settings. In
		 * general, if the breakpoint is not in a consistent, enabled, and effective state, but it
		 * could be, then toggling it should attempt to make it so. If it is consistent, enabled,
		 * and effective, then toggling it should make it consistent, disabled, and effective. If it
		 * is not mapped, the state should toggle between enabled and disabled, but ineffective.
		 * 
		 * <p>
		 * This will always return one of {@link #ENABLED} or {@link #DISABLED}, indicating what
		 * action should be taken on the logical breakpoint. A breakpoint that is ineffective,
		 * because it is not mapped, will remain ineffective.
		 * 
		 * @param mapped true if the breakpoint is mapped, as interpreted by the action context
		 * @return the resulting state
		 */
		public Enablement getToggled(boolean mapped) {
			// If not mapped, just toggle. If mapped, consider any other state "disabled"
			// This will cause most first toggles to make it consistent enabled-effective.
			boolean en = mapped ? this == ENABLED : enabled;
			return en ? DISABLED : ENABLED; // The actual toggle (and type conversion)
		}
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
	 * <p>
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
	 * <p>
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
	 * <p>
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
	 * <p>
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
	 * <p>
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
	 * <p>
	 * Presuming the breakpoint is mappable to the given trace, if no breakpoint of the same kind
	 * exists at the mapped address, then this will create a new breakpoint. Note, depending on the
	 * debugging model, the enabled or created breakpoint may apply to more than the given trace.
	 * 
	 * <p>
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
	 * <p>
	 * Note this will not create any new breakpoints. It will disable all breakpoints of the same
	 * kind at the mapped address. Note, depending on the debugging model, the disabled breakpoint
	 * may apply to more than the given trace.
	 * 
	 * <p>
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
	 * <p>
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
	 * <p>
	 * This affects the mapped program, if applicable, and all open and live traces. Note, depending
	 * on the debugging model, the enabled or created breakpoints may apply to more targets.
	 * 
	 * <p>
	 * This simply issues the command. The logical breakpoint is updated only when the resulting
	 * events are processed.
	 * 
	 * @return a future which completes when the breakpoint is enabled
	 */
	CompletableFuture<Void> enable();

	/**
	 * Disable this breakpoint everywhere in the tool.
	 * 
	 * <p>
	 * This affects the mapped program, if applicable, and all open and live traces. Note, depending
	 * on the debugging model, the disabled breakpoints may apply to more targets.
	 * 
	 * <p>
	 * This simply issues the command. The logical breakpoint is updated only when the resulting
	 * events are processed.
	 * 
	 * @return a future which completes when the breakpoint is disabled
	 */
	CompletableFuture<Void> disable();

	/**
	 * Delete this breakpoint everywhere in the tool.
	 * 
	 * <p>
	 * This presumes the breakpoint's specifications are deletable. This affects the mapped program,
	 * if applicable, and all open and live traces. Note, depending on the debugging model, the
	 * deleted breakpoints may be removed from more targets.
	 * 
	 * <p>
	 * This simply issues the command. The logical breakpoint is updated only when the resulting
	 * events are processed.
	 * 
	 * @return a future which completes when the breakpoint is deleted
	 */
	CompletableFuture<Void> delete();
}
