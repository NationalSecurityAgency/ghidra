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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
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
	public enum ProgramMode {
		/**
		 * A placeholder state when the program bookmark state is not applicable
		 */
		NONE {
			@Override
			public State combineTrace(TraceMode traceMode, Perspective perspective) {
				switch (traceMode) {
					case NONE:
						return State.NONE;
					case MISSING:
						return State.NONE;
					case ENABLED:
						return State.INCONSISTENT_ENABLED;
					case DISABLED:
						return State.INCONSISTENT_DISABLED;
					case MIXED:
						return State.INCONSISTENT_MIXED;
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
			public State combineTrace(TraceMode traceMode, Perspective perspective) {
				switch (traceMode) {
					case NONE:
						return State.NONE;
					case MISSING:
						return State.NONE;
					case ENABLED:
						return State.INCONSISTENT_ENABLED;
					case DISABLED:
						return State.INCONSISTENT_DISABLED;
					case MIXED:
						return State.INCONSISTENT_MIXED;
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
			public State combineTrace(TraceMode traceMode, Perspective perspective) {
				switch (traceMode) {
					case NONE:
					case MISSING:
						switch (perspective) {
							case LOGICAL:
								return State.INEFFECTIVE_ENABLED;
							case TRACE:
								return State.NONE;
						}
					case ENABLED:
						return State.ENABLED;
					case DISABLED:
						switch (perspective) {
							case LOGICAL:
								return State.INCONSISTENT_ENABLED;
							case TRACE:
								return State.INCONSISTENT_DISABLED;
						}
					case MIXED:
						switch (perspective) {
							case LOGICAL:
								return State.INCONSISTENT_ENABLED;
							case TRACE:
								return State.INCONSISTENT_MIXED;
						}
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
			public State combineTrace(TraceMode traceMode, Perspective perspective) {
				switch (traceMode) {
					case NONE:
					case MISSING:
						switch (perspective) {
							case LOGICAL:
								return State.INEFFECTIVE_DISABLED;
							case TRACE:
								return State.NONE;
						}
					case ENABLED:
						switch (perspective) {
							case LOGICAL:
								return State.INCONSISTENT_DISABLED;
							case TRACE:
								return State.INCONSISTENT_ENABLED;
						}
					case DISABLED:
						return State.DISABLED;
					case MIXED:
						switch (perspective) {
							case LOGICAL:
								return State.INCONSISTENT_DISABLED;
							case TRACE:
								return State.INCONSISTENT_MIXED;
						}
						return State.INCONSISTENT_MIXED;
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
		 * @param traceMode the mode of its locations
		 * @param perspective the perspective
		 * @return the logical state
		 */
		public abstract State combineTrace(TraceMode traceMode, Perspective perspective);
	}

	public enum Perspective {
		LOGICAL, TRACE;
	}

	/**
	 * The state of a logical breakpoint's trace/target locations
	 */
	public enum TraceMode {
		/**
		 * A placeholder mode when no traces are involved
		 */
		NONE {
			@Override
			public TraceMode combine(TraceMode that) {
				return that;
			}
		},
		/**
		 * The mode when the breakpoint is missing from one or more of its mapped locations
		 */
		MISSING {
			@Override
			public TraceMode combine(TraceMode that) {
				return MISSING;
			}
		},
		/**
		 * The mode when all mapped locations are placed and enabled
		 */
		ENABLED {
			@Override
			public TraceMode combine(TraceMode that) {
				switch (that) {
					case NONE:
					case ENABLED:
						return ENABLED;
					case DISABLED:
					case MIXED:
						return MIXED;
					case MISSING:
						return MISSING;
					default:
						throw new AssertionError();
				}
			}
		},
		/**
		 * The mode when all mapped locations are placed and disabled
		 */
		DISABLED {
			@Override
			public TraceMode combine(TraceMode that) {
				switch (that) {
					case NONE:
					case DISABLED:
						return DISABLED;
					case ENABLED:
					case MIXED:
						return MIXED;
					case MISSING:
						return MISSING;
					default:
						throw new AssertionError();
				}
			}
		},
		/**
		 * The mode when all mapped locations are placed, but some are enabled, and some are
		 * disabled
		 */
		MIXED {
			@Override
			public TraceMode combine(TraceMode that) {
				switch (that) {
					case NONE:
					case ENABLED:
					case DISABLED:
					case MIXED:
						return MIXED;
					case MISSING:
						return MISSING;
					default:
						throw new AssertionError();
				}
			}
		};

		/**
		 * Convert a boolean to trace breakpoint mode
		 * 
		 * @param enabled true for {@link #ENABLED}, false for {@link #DISABLED}
		 * @return the state
		 */
		public static TraceMode fromBool(boolean enabled) {
			return enabled ? ENABLED : DISABLED;
		}

		/**
		 * For locations of the same logical breakpoint, compose the mode
		 * 
		 * @param that the other state
		 * @return the composed state
		 */
		public abstract TraceMode combine(TraceMode that);
	}

	/**
	 * The mode of a logical breakpoint
	 * 
	 * <p>
	 * Depending on context this may describe the mode from the perspective of a program, where
	 * breakpoints are saved from session to session; or this may describe the mode from the
	 * perspective of one or more traces/targets:
	 * 
	 * <p>
	 * If the breakpoint is a lone breakpoint, meaning Ghidra cannot determine to what program it
	 * belongs, then this describes the mode of that trace breakpoint.
	 * 
	 * <p>
	 * If the breakpoint is mapped, meaning Ghidra can determine to what program it belongs and at
	 * what address, but it is not bookmarked, then for the static context, this describes the mode
	 * of the participating trace breakpoints. If the breakpoint is bookmarked, then for the static
	 * context, this describes the mode of that bookmark. For the dynamic context, this describes
	 * the mode of the trace's breakpoint, ignoring the presence or state of the bookmark. Note that
	 * the bookmark and trace modes may disagree. The displayed mode is still determined by context,
	 * but it will be marked as inconsistent. See {@link Consistency}.
	 */
	public enum Mode {
		/** All locations are enabled */
		ENABLED,
		/** All locations are disabled */
		DISABLED,
		/** Has both enabled and disabled trace locations */
		MIXED;

		public Mode sameAddress(Mode that) {
			if (this == Objects.requireNonNull(that)) {
				return this;
			}
			return MIXED;
		}
	}

	/**
	 * The consistency of a logical breakpoint
	 * 
	 * <p>
	 * When operating as designed, all breakpoints should be in the {@link #NORMAL} state. This
	 * indicates that the breakpoint's bookmark and all trace locations agree on the mode.
	 * Exceptions do happen, and they should be indicated to the user:
	 * 
	 * <p>
	 * If the breakpoint is a lone breakpoint, meaning Ghidra cannot determine to what program it
	 * belongs, then the breakpoint is always {@link #INCONSISTENT}, because Ghidra uses program
	 * bookmarks to save breakpoints.
	 * 
	 * <p>
	 * If the breakpoint is mapped, meaning Ghidra can determine to what program it belongs and at
	 * what address, but it is not bookmarked, then the breakpoint is {@link #INCONSISTENT}. If it
	 * is bookmarked, but the bookmark disagrees, then the breakpoint is {@link #INCONSISTENT}. A
	 * breakpoint that is bookmarked but has no trace locations, or is missing from any
	 * participating trace, is {@link #INEFFECTIVE}.
	 * 
	 * @implNote These are ordered by priority, highest last.
	 */
	public enum Consistency {
		/** the bookmark and locations all agree */
		NORMAL,
		/** has a bookmark but one or more trace locations is missing */
		INEFFECTIVE,
		/** has a trace location but is not bookmarked, or the bookmark disagrees */
		INCONSISTENT;

		public Consistency sameAddress(Consistency that) {
			return Consistency.values()[Math.max(this.ordinal(), that.ordinal())];
		}
	}

	/**
	 * The state of a logical breakpoint
	 * 
	 * <p>
	 * Because a breakpoint is comprised of possibly many locations on target or among several
	 * targets, as well as a saved bookmark in a program, the "state" can get fairly complex. This
	 * is an attempt to enumerate these states while preserving enough information about the
	 * breakpoint to display it in various contexts, hopefully informing more than confusing.
	 * 
	 * <p>
	 * In essence, this is the cross product of {@link Mode} and {@link Consistency} with an
	 * additional {@link #NONE} option.
	 * 
	 * <p>
	 * A breakpoint is simply {@link #ENABLED} or {@link #DISABLED} if it is maped and all its
	 * locations and bookmark agree. Ideally, all breakpoints would be in one of these two states.
	 */
	public enum State {
		/**
		 * A placeholder state, usually indicating the logical breakpoint should not exist
		 * 
		 * <p>
		 * This state should not ever be assigned to any actual breakpoint, except if that
		 * breakpoint is ephemeral and about to be removed. This value may appear during
		 * computations and is a suitable default placeholder for editors and renderers.
		 */
		NONE(null, null, null, null),
		/**
		 * The breakpoint is enabled, and all locations and its bookmark agree
		 */
		ENABLED(Mode.ENABLED, Consistency.NORMAL, DebuggerResources.NAME_BREAKPOINT_MARKER_ENABLED, DebuggerResources.ICON_BREAKPOINT_MARKER_ENABLED),
		/**
		 * The breakpoint is disabled, and all locations and its bookmark agree
		 */
		DISABLED(Mode.DISABLED, Consistency.NORMAL, DebuggerResources.NAME_BREAKPOINT_MARKER_DISABLED, DebuggerResources.ICON_BREAKPOINT_MARKER_DISABLED),
		/**
		 * There are multiple logical breakpoints at this address, and they are all saved and
		 * effective, but some are enabled, and some are disabled.
		 */
		MIXED(Mode.MIXED, Consistency.NORMAL, DebuggerResources.NAME_BREAKPOINT_MARKER_MIXED, DebuggerResources.ICON_BREAKPOINT_MARKER_MIXED),
		/**
		 * The breakpoint is saved as enabled, but one or more trace locations are absent.
		 */
		INEFFECTIVE_ENABLED(Mode.ENABLED, Consistency.INEFFECTIVE, DebuggerResources.NAME_BREAKPOINT_MARKER_INEFF_EN, DebuggerResources.ICON_BREAKPOINT_MARKER_INEFF_EN),
		/**
		 * The breakpoint is saved as disabled, and one or more trace locations are absent.
		 */
		INEFFECTIVE_DISABLED(Mode.DISABLED, Consistency.INEFFECTIVE, DebuggerResources.NAME_BREAKPOINT_MARKER_INEFF_DIS, DebuggerResources.ICON_BREAKPOINT_MARKER_INEFF_DIS),
		/**
		 * There are multiple logical breakpoints at this address, and they are all saved, but at
		 * least one is ineffective; furthermore, some are enabled, and some are disabled.
		 */
		INEFFECTIVE_MIXED(Mode.MIXED, Consistency.INEFFECTIVE, DebuggerResources.NAME_BREAKPOINT_MARKER_INEFF_MIX, DebuggerResources.ICON_BREAKPOINT_MARKER_INEFF_MIX),
		/**
		 * The breakpoint is enabled, and all locations agree, but the bookmark is absent or
		 * disagrees.
		 */
		INCONSISTENT_ENABLED(Mode.ENABLED, Consistency.INCONSISTENT, DebuggerResources.NAME_BREAKPOINT_MARKER_INCON_EN, DebuggerResources.ICON_BREAKPOINT_MARKER_INCON_EN),
		/**
		 * The breakpoint is disabled, and all locations agree, but the bookmark is absent or
		 * disagrees.
		 */
		INCONSISTENT_DISABLED(Mode.DISABLED, Consistency.INCONSISTENT, DebuggerResources.NAME_BREAKPOINT_MARKER_INCON_DIS, DebuggerResources.ICON_BREAKPOINT_MARKER_INCON_DIS),
		/**
		 * The breakpoint is terribly inconsistent: its locations disagree, and the bookmark may be
		 * absent.
		 */
		INCONSISTENT_MIXED(Mode.MIXED, Consistency.INCONSISTENT, DebuggerResources.NAME_BREAKPOINT_MARKER_INCON_MIX, DebuggerResources.ICON_BREAKPOINT_MARKER_INCON_MIX);

		public final Mode mode;
		public final Consistency consistency;
		public final String display;
		public final Icon icon;

		State(Mode mode, Consistency consistency, String display, Icon icon) {
			this.mode = mode;
			this.consistency = consistency;
			this.display = display;
			this.icon = icon;
		}

		public static State fromFields(Mode mode, Consistency consistency) {
			if (mode == null && consistency == null) {
				return NONE;
			}
			switch (mode) {
				case ENABLED:
					switch (consistency) {
						case NORMAL:
							return ENABLED;
						case INEFFECTIVE:
							return INEFFECTIVE_ENABLED;
						case INCONSISTENT:
							return INCONSISTENT_ENABLED;
					}
				case DISABLED:
					switch (consistency) {
						case NORMAL:
							return DISABLED;
						case INEFFECTIVE:
							return INEFFECTIVE_DISABLED;
						case INCONSISTENT:
							return INCONSISTENT_DISABLED;
					}
				case MIXED:
					switch (consistency) {
						case NORMAL:
							return MIXED;
						case INEFFECTIVE:
							return INEFFECTIVE_MIXED;
						case INCONSISTENT:
							return INCONSISTENT_MIXED;
					}
			}
			throw new AssertionError();
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
		public State sameAdddress(State that) {
			if (this == NONE) {
				return that;
			}
			if (that == NONE) {
				return this;
			}
			Mode mode = this.mode.sameAddress(that.mode);
			Consistency consistency = this.consistency.sameAddress(that.consistency);
			return fromFields(mode, consistency);
		};

		/**
		 * For logical breakpoints which appear at the same address, compose their state
		 * 
		 * @see #sameAdddress(State)
		 * @param col a collection of states derived from logical breakpoints at the same address
		 * @return the composed state
		 */
		public static State sameAddress(Collection<State> col) {
			State result = NONE;
			for (State state : col) {
				result = result.sameAdddress(state);
			}
			return result;
		}

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
		public State getToggled(boolean mapped) {
			if (mapped && isIneffective()) {
				return ENABLED;
			}
			return isDisabled() ? ENABLED : DISABLED;
		}

		public boolean isNormal() {
			return consistency == Consistency.NORMAL;
		}

		public boolean isEnabled() {
			return mode != Mode.DISABLED; // mixed is considered, in part, enabled
		}

		boolean isDisabled() {
			return mode != Mode.ENABLED; // mixed is considered, in part, disabled
		}

		public boolean isEffective() {
			return consistency != Consistency.INEFFECTIVE;
		}

		public boolean isIneffective() {
			return consistency == Consistency.INEFFECTIVE;
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
	 * If the logical breakpoint is present in a program, get its name.
	 * 
	 * @return the name, or the empty string
	 */
	String getName();

	/**
	 * If the logical breakpoint is present in a program, set its name.
	 * 
	 * @param name the name
	 * @throws IllegalStateException if the breakpoint is not present in a program
	 */
	void setName(String name);

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
	 * @return a copy of the set of traces
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
	 * Compute the state for the given program.
	 * 
	 * @param program the program
	 * @return the state
	 */
	State computeStateForProgram(Program program);

	/**
	 * Compute the state for the given trace.
	 * 
	 * @param trace the trace
	 * @return the state
	 */
	State computeStateForTrace(Trace trace);

	/**
	 * Compute the state for the given location.
	 * 
	 * <p>
	 * This is just the location's mode combined with that of the static bookmark.
	 * 
	 * @param loc the location
	 * @return the state
	 */
	State computeStateForLocation(TraceBreakpoint loc);

	/**
	 * Compute the state for all involved traces and program.
	 * 
	 * @return the state
	 */
	State computeState();

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
