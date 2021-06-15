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
package ghidra.app.plugin.core.debug.service.breakpoint;

import java.util.*;

import com.google.common.collect.Collections2;

import ghidra.app.services.LogicalBreakpoint;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.util.Msg;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

interface LogicalBreakpointInternal extends LogicalBreakpoint {
	public static class ProgramBreakpoint {
		public static Set<TraceBreakpointKind> kindsFromBookmark(Bookmark mark) {
			String[] parts = mark.getCategory().split(";");
			Set<TraceBreakpointKind> result = TraceBreakpointKindSet.decode(parts[0], false);
			if (result.isEmpty()) {
				Msg.warn(TraceBreakpointKind.class,
					"Decoded empty set of kinds from bookmark. Assuming SW_EXECUTE");
				return Set.of(TraceBreakpointKind.SW_EXECUTE);
			}
			return result;
		}

		public static long lengthFromBookmark(Bookmark mark) {
			String[] parts = mark.getCategory().split(";");
			if (parts.length < 2) {
				Msg.warn(DebuggerLogicalBreakpointServicePlugin.class,
					"No length for bookmark breakpoint. Assuming 1.");
				return 1;
			}
			try {
				long length = Long.parseLong(parts[1]);
				if (length <= 0) {
					Msg.warn(DebuggerLogicalBreakpointServicePlugin.class,
						"Non-positive length for bookmark breakpoint? Using 1.");
					return 1;
				}
				return length;
			}
			catch (NumberFormatException e) {
				Msg.warn(DebuggerLogicalBreakpointServicePlugin.class,
					"Ill-formatted bookmark breakpoint length: " + e + ". Using 1.");
				return 1;
			}
		}

		private final Program program;
		private final Address address;
		private final ProgramLocation location;
		private final long length;
		private final Set<TraceBreakpointKind> kinds;

		private Bookmark eBookmark; // when present
		private Bookmark dBookmark; // when present

		public ProgramBreakpoint(Program program, Address address, long length,
				Set<TraceBreakpointKind> kinds) {
			this.program = program;
			this.address = address;
			this.location = new ProgramLocation(program, address);
			this.length = length;
			this.kinds = kinds;
		}

		@Override
		public String toString() {
			if (eBookmark != null) {
				return String.format("<enabled %s(%s) at %s in %s>", eBookmark.getTypeString(),
					eBookmark.getCategory(), eBookmark.getAddress(), program.getName());
			}
			else if (dBookmark != null) {
				return String.format("<disabled %s(%s) at %s in %s>", dBookmark.getTypeString(),
					dBookmark.getCategory(), dBookmark.getAddress(), program.getName());
			}
			else {
				return String.format("<absent at %s in %s>", address, program.getName());
			}
		}

		public ProgramLocation getLocation() {
			return location;
		}

		public ProgramEnablement computeEnablement() {
			if (eBookmark != null) {
				return ProgramEnablement.ENABLED;
			}
			if (dBookmark != null) {
				return ProgramEnablement.DISABLED;
			}
			else {
				return ProgramEnablement.MISSING;
			}
		}

		public boolean isEmpty() {
			return eBookmark == null && dBookmark == null;
		}

		public void deleteFromProgram() {
			try (UndoableTransaction tid =
				UndoableTransaction.start(program, "Clear breakpoint", false)) {
				BookmarkManager bookmarkManager = program.getBookmarkManager();
				if (eBookmark != null) {
					bookmarkManager.removeBookmark(eBookmark);
				}
				if (dBookmark != null) {
					bookmarkManager.removeBookmark(dBookmark);
				}
				// (e,d)Bookmark Gets nulled on program change callback
				// If null here, logical breakpoint manager will get confused
				tid.commit();
			}
		}

		public boolean canMerge(Program candProgram, Bookmark candBookmark) {
			if (program != candProgram) {
				return false;
			}
			if (!address.equals(candBookmark.getAddress())) {
				return false;
			}
			if (length != lengthFromBookmark(candBookmark)) {
				return false;
			}
			if (!Objects.equals(kinds, kindsFromBookmark(candBookmark))) {
				return false;
			}
			return true;
		}

		public Program getProgram() {
			return program;
		}

		public boolean add(Bookmark bookmark) {
			if (BREAKPOINT_ENABLED_BOOKMARK_TYPE.equals(bookmark.getTypeString())) {
				if (eBookmark == bookmark) {
					return false;
				}
				eBookmark = bookmark;
				return true;
			}
			if (BREAKPOINT_DISABLED_BOOKMARK_TYPE.equals(bookmark.getTypeString())) {
				if (dBookmark == bookmark) {
					return false;
				}
				dBookmark = bookmark;
				return true;
			}
			return false;
		}

		public boolean remove(Bookmark bookmark) {
			if (eBookmark == bookmark) {
				eBookmark = null;
				return true;
			}
			if (dBookmark == bookmark) {
				dBookmark = null;
				return true;
			}
			return false;
		}

		public Bookmark getBookmark() {
			if (eBookmark != null) {
				return eBookmark;
			}
			return dBookmark;
		}

		public boolean isEnabled() {
			return computeEnablement() == ProgramEnablement.ENABLED;
		}

		public boolean isDisabled() {
			return computeEnablement() == ProgramEnablement.DISABLED;
		}

		public String computeCategory() {
			return TraceBreakpointKindSet.encode(kinds) + ";" + Long.toUnsignedString(length);
		}

		public void enable() {
			if (isEnabled()) {
				return;
			}
			try (UndoableTransaction tid =
				UndoableTransaction.start(program, "Enable breakpoint", false)) {
				BookmarkManager manager = program.getBookmarkManager();
				String catStr = computeCategory();
				manager.setBookmark(address, BREAKPOINT_ENABLED_BOOKMARK_TYPE, catStr, "");
				manager.removeBookmarks(new AddressSet(address), BREAKPOINT_DISABLED_BOOKMARK_TYPE,
					catStr, TaskMonitor.DUMMY);
				tid.commit();
			}
			catch (CancelledException e) {
				throw new AssertionError(e);
			}
		}

		public void disable() {
			if (isDisabled()) {
				return;
			}
			try (UndoableTransaction tid =
				UndoableTransaction.start(program, "Disable breakpoint", false)) {
				BookmarkManager manager = program.getBookmarkManager();
				String catStr = computeCategory();
				manager.setBookmark(address, BREAKPOINT_DISABLED_BOOKMARK_TYPE, catStr, "");
				manager.removeBookmarks(new AddressSet(address), BREAKPOINT_ENABLED_BOOKMARK_TYPE,
					catStr, TaskMonitor.DUMMY);
				tid.commit();
			}
			catch (CancelledException e) {
				throw new AssertionError(e);
			}
		}
	}

	static class TraceBreakpointSet {
		private static class IDHashed<T> {
			final T obj;

			public IDHashed(T obj) {
				this.obj = obj;
			}

			@Override
			public String toString() {
				return obj.toString();
			}

			@Override
			public int hashCode() {
				return System.identityHashCode(obj);
			}

			@Override
			public boolean equals(Object o) {
				if (!(o instanceof IDHashed<?>)) {
					return false;
				}
				IDHashed<?> that = (IDHashed<?>) o;
				return this.obj.equals(that.obj);
			}
		}

		private final TraceRecorder recorder;
		private final Trace trace;
		private final Address address;
		private Set<IDHashed<TraceBreakpoint>> breakpoints = new HashSet<>();

		public TraceBreakpointSet(TraceRecorder recorder, Address address) {
			this.recorder = recorder;
			this.trace = recorder.getTrace();
			this.address = address;
		}

		@Override
		public String toString() {
			return String.format("<at %s in %s: %s>", address, trace.getName(), breakpoints);
		}

		public Trace getTrace() {
			return trace;
		}

		public Address getAddress() {
			return address;
		}

		public Address computeTargetAddress() {
			// TODO: Can this change? If not, can compute in constructor.
			return recorder.getMemoryMapper().traceToTarget(address);
		}

		public TraceEnablement computeEnablement() {
			TraceEnablement en = TraceEnablement.MISSING;
			for (IDHashed<TraceBreakpoint> bpt : breakpoints) {
				en = en.combine(TraceEnablement.fromBool(bpt.obj.isEnabled()));
				if (en == TraceEnablement.MIXED) {
					return en;
				}
			}
			return en;
		}

		public boolean isEmpty() {
			return breakpoints.isEmpty();
		}

		public Collection<TraceBreakpoint> getBreakpoints() {
			return Collections2.transform(breakpoints, e -> e.obj);
		}

		public boolean add(TraceBreakpoint bpt) {
			return breakpoints.add(new IDHashed<>(bpt));
		}

		public boolean canMerge(TraceBreakpoint bpt) {
			if (trace != bpt.getTrace()) {
				return false;
			}
			if (!address.equals(bpt.getMinAddress())) {
				return false;
			}
			return true;
		}

		public boolean remove(TraceBreakpoint bpt) {
			return breakpoints.remove(new IDHashed<>(bpt));
		}

		/**
		 * Plan to enable a logical breakpoint within the trace.
		 * 
		 * <p>
		 * This method prefers to use the existing breakpoint specifications which result in
		 * breakpoints at this address. In other words, it favors what the user has already done to
		 * effect a breakpoint at this logical breakpoint's address. If there is no such existing
		 * specification, then it attempts to place a new breakpoint via the target's breakpoint
		 * container, usually resulting in a new spec, which should effect exactly the one specified
		 * address.
		 * 
		 * <p>
		 * This method must convert applicable addresses to the target space. If the address cannot
		 * be mapped, it's usually because this logical breakpoint does not apply to the given
		 * trace's target. E.g., the trace may not have a live target, or the logical breakpoint may
		 * be in a module not loaded by the trace.
		 * 
		 * @param actions the action set to populate
		 * @param kind the kind of breakpoint
		 * @return a future which completes when the plan is ready
		 */
		public void planEnable(BreakpointActionSet actions, long length,
				Collection<TraceBreakpointKind> kinds) {
			if (breakpoints.isEmpty()) {
				Set<TargetBreakpointKind> tKinds =
					TraceRecorder.traceToTargetBreakpointKinds(kinds);

				for (TargetBreakpointSpecContainer cont : recorder
						.collectBreakpointContainers(null)) {
					LinkedHashSet<TargetBreakpointKind> supKinds = new LinkedHashSet<>(tKinds);
					supKinds.retainAll(cont.getSupportedBreakpointKinds());
					actions.add(new PlaceBreakpointActionItem(cont, computeTargetAddress(), length,
						supKinds));
				}
				return;
			}
			for (IDHashed<TraceBreakpoint> bpt : breakpoints) {
				TargetBreakpointLocation loc = recorder.getTargetBreakpoint(bpt.obj);
				if (loc == null) {
					continue;
				}
				actions.planEnable(loc);
			}
		}

		public void planDisable(BreakpointActionSet actions, long length,
				Collection<TraceBreakpointKind> kinds) {
			Set<TargetBreakpointKind> tKinds = TraceRecorder.traceToTargetBreakpointKinds(kinds);
			Address targetAddr = computeTargetAddress();
			for (TargetBreakpointLocation loc : recorder.collectBreakpoints(null)) {
				if (!targetAddr.equals(loc.getAddress())) {
					continue;
				}
				if (length != loc.getLength().longValue()) {
					continue;
				}
				TargetBreakpointSpec spec = loc.getSpecification();
				if (!Objects.equals(spec.getKinds(), tKinds)) {
					continue;
				}
				actions.planDisable(loc);
			}
		}

		public void planDelete(BreakpointActionSet actions, long length,
				Set<TraceBreakpointKind> kinds) {
			Set<TargetBreakpointKind> tKinds = TraceRecorder.traceToTargetBreakpointKinds(kinds);
			Address targetAddr = computeTargetAddress();
			for (TargetBreakpointLocation loc : recorder.collectBreakpoints(null)) {
				if (!targetAddr.equals(loc.getAddress())) {
					continue;
				}
				if (length != loc.getLength().longValue()) {
					continue;
				}
				TargetBreakpointSpec spec = loc.getSpecification();
				if (!Objects.equals(spec.getKinds(), tKinds)) {
					continue;
				}
				actions.planDelete(loc);
			}
		}
	}

	/**
	 * Set the expected address for trace breakpoints in the given trace
	 * 
	 * @param recorder the recorder for the given trace
	 * @param address the address of this logical breakpoint in the given trace
	 */
	void setTraceAddress(TraceRecorder recorder, Address address);

	boolean canMerge(Program program, Bookmark bookmark);

	/**
	 * Check if this logical breakpoint can subsume the given candidate trace breakpoint
	 * 
	 * Note that logical breakpoints only include trace breakpoints for traces being actively
	 * recorded. All statuses regarding trace breakpoints are derived from the target breakpoints,
	 * i.e., they show the present status, regardless of the view's current time. A separate
	 * breakpoint history provider handles displaying records from the past, including dead traces.
	 * 
	 * @param breakpoint the trace breakpoint to check
	 * @return true if it can be aggregated.
	 */
	boolean canMerge(TraceBreakpoint breakpoint);

	boolean trackBreakpoint(Bookmark bookmark);

	boolean trackBreakpoint(TraceBreakpoint breakpoint);

	boolean untrackBreakpoint(TraceBreakpoint breakpoint);

	boolean untrackBreakpoint(Program program, Bookmark bookmark);

	/**
	 * Collect actions to enable a logical breakpoint.
	 * 
	 * @param actions the destination action set (plan)
	 * @param trace a trace, if actions should be limited to the given trace
	 * @return a future which completes when the actions are populated
	 */
	void planEnable(BreakpointActionSet actions, Trace trace);

	/**
	 * Collect actions to disable a logical breakpoint.
	 * 
	 * @param actions the destination action set (plan)
	 * @param trace a trace, if actions should be limited to the given trace
	 * @return a future which completes when the actions are populated
	 */
	void planDisable(BreakpointActionSet actions, Trace trace);

	/**
	 * Collect actions to delete a logical breakpoint.
	 * 
	 * @param actions the destination action set (plan)
	 * @param trace a trace, if actions should be limited to the given trace
	 * @return a future which completes when the actions are populated
	 */
	void planDelete(BreakpointActionSet actions, Trace trace);
}
