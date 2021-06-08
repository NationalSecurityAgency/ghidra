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
import java.util.concurrent.CompletableFuture;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import org.apache.commons.collections4.IteratorUtils;

import com.google.common.collect.Range;

import generic.CatenatedCollection;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceOpenedPluginEvent;
import ghidra.app.plugin.core.debug.service.breakpoint.LogicalBreakpointInternal.ProgramBreakpoint;
import ghidra.app.services.*;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceBreakpointChangeType;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.datastruct.CollectionChangeListener;
import ghidra.util.datastruct.ListenerSet;

@PluginInfo(
	shortDescription = "Debugger logical breakpoints service plugin",
	description = "Aggregates breakpoints from open programs and live traces",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		ProgramOpenedPluginEvent.class,
		ProgramClosedPluginEvent.class,
		TraceOpenedPluginEvent.class,
		TraceClosedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerTraceManagerService.class,
		DebuggerModelService.class,
		DebuggerStaticMappingService.class,
	},
	servicesProvided = {
		DebuggerLogicalBreakpointService.class,
	})
public class DebuggerLogicalBreakpointServicePlugin extends Plugin
		implements DebuggerLogicalBreakpointService {

	private static class AddCollector implements AutoCloseable {
		private final LogicalBreakpointsChangeListener l;
		private final Set<LogicalBreakpoint> added = new HashSet<>();
		private final Set<LogicalBreakpoint> updated = new HashSet<>();

		public AddCollector(LogicalBreakpointsChangeListener l) {
			this.l = l;
		}

		protected void added(LogicalBreakpoint lb) {
			added.add(lb);
		}

		protected void updated(LogicalBreakpoint lb) {
			updated.add(lb);
		}

		@Override
		public void close() {
			updated.removeAll(added); // Feels hackish, but it works
			if (!updated.isEmpty()) {
				l.breakpointsUpdated(updated);
			}
			if (!added.isEmpty()) {
				l.breakpointsAdded(added);
			}
		}

		public void deconflict(RemoveCollector r) {
			updated.addAll(r.updated);
			r.updated.clear();
		}
	}

	private static class RemoveCollector implements AutoCloseable {
		private final LogicalBreakpointsChangeListener l;
		private final Set<LogicalBreakpoint> removed = new HashSet<>();
		private final Set<LogicalBreakpoint> updated = new HashSet<>();

		public RemoveCollector(LogicalBreakpointsChangeListener l) {
			this.l = l;
		}

		protected void updated(LogicalBreakpoint lb) {
			updated.add(lb);
		}

		protected void removed(LogicalBreakpoint lb) {
			removed.add(lb);
		}

		@Override
		public void close() {
			updated.removeAll(removed); // Feels hackish, but it works
			if (!removed.isEmpty()) {
				l.breakpointsRemoved(removed);
			}
			if (!updated.isEmpty()) {
				l.breakpointsUpdated(updated);
			}
		}
	}

	protected class TrackRecordersListener implements CollectionChangeListener<TraceRecorder> {
		@Override
		public void elementAdded(TraceRecorder element) {
			Swing.runIfSwingOrRunLater(() -> traceRecordingStarted(element));
		}

		@Override
		public void elementRemoved(TraceRecorder element) {
			Swing.runIfSwingOrRunLater(() -> traceRecordingStopped(element));
		}
	}

	protected class TrackMappingsListener implements DebuggerStaticMappingChangeListener {
		@Override
		public void mappingsChanged(Set<Trace> affectedTraces, Set<Program> affectedPrograms) {
			// Msg.debug(this, "Mappings changed: " + affectedTraces + "," + affectedPrograms);
			synchronized (lock) {
				// Msg.debug(this, "Processing map change");
				Set<Trace> additionalTraces = new HashSet<>(affectedTraces);
				Set<Program> additionalPrograms = new HashSet<>(affectedPrograms);
				try (RemoveCollector r = new RemoveCollector(changeListeners.fire)) {
					// Though all mapped breakpoints are in program infos,
					// That program may not be in the affected list, esp., if just closed
					for (Trace t : affectedTraces) {
						InfoPerTrace info = traceInfos.get(t);
						if (info != null) {
							info.forgetMismappedBreakpoints(r, additionalTraces,
								additionalPrograms);
						}
					}
					for (Program p : affectedPrograms) {
						InfoPerProgram info = programInfos.get(p);
						if (info != null) {
							info.forgetMismappedBreakpoints(r, additionalTraces,
								additionalPrograms);
						}
					}
				}
				for (Trace t : additionalTraces) {
					InfoPerTrace info = traceInfos.get(t);
					if (info != null) {
						info.reloadBreakpoints();
					}
				}
				for (Program p : additionalPrograms) {
					InfoPerProgram info = programInfos.get(p);
					if (info != null) {
						info.reloadBreakpoints();
					}
				}
			}
		}
	}

	private class TraceBreakpointsListener extends TraceDomainObjectListener {
		private final InfoPerTrace info;

		public TraceBreakpointsListener(InfoPerTrace info) {
			// TODO: What if recorder advances past a trace breakpoint?
			// Tends never to happen during recording, since upper is unbounded
			// (Same in break provider for locations)
			this.info = info;

			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());
			listenFor(TraceBreakpointChangeType.ADDED, this::breakpointAdded);
			listenFor(TraceBreakpointChangeType.CHANGED, this::breakpointChanged);
			listenFor(TraceBreakpointChangeType.LIFESPAN_CHANGED, this::breakpointLifespanChanged);
			listenFor(TraceBreakpointChangeType.DELETED, this::breakpointDeleted);
		}

		private void objectRestored() {
			// Msg.debug(this, "Restored: " + info.trace);
			synchronized (lock) {
				info.reloadBreakpoints();
			}
		}

		private void breakpointAdded(TraceBreakpoint breakpoint) {
			// Msg.debug(this, "Breakpoint added: " + breakpoint);
			if (!breakpoint.getLifespan().contains(info.recorder.getSnap())) {
				// NOTE: User/script probably added historical breakpoint
				return;
			}
			try (AddCollector c = new AddCollector(changeListeners.fire)) {
				synchronized (lock) {
					// Msg.debug(this, "Processing breakpoint add");
					info.trackTraceBreakpoint(breakpoint, c, false);
				}
			}
		}

		private void breakpointChanged(TraceBreakpoint breakpoint) {
			if (!breakpoint.getLifespan().contains(info.recorder.getSnap())) {
				return;
			}
			try (AddCollector c = new AddCollector(changeListeners.fire)) {
				synchronized (lock) {
					info.trackTraceBreakpoint(breakpoint, c, true);
				}
			}
		}

		private void breakpointLifespanChanged(TraceAddressSpace spaceIsNull,
				TraceBreakpoint breakpoint, Range<Long> oldSpan, Range<Long> newSpan) {
			// Msg.debug(this, "Breakpoint span: " + breakpoint);
			// NOTE: User/script probably modified historical breakpoint
			boolean isInOld = oldSpan.contains(info.recorder.getSnap());
			boolean isInNew = newSpan.contains(info.recorder.getSnap());
			if (isInOld == isInNew) {
				return;
			}
			if (isInOld) {
				try (RemoveCollector c = new RemoveCollector(changeListeners.fire)) {
					synchronized (lock) {
						info.forgetTraceBreakpoint(breakpoint, c);
					}
				}
			}
			else {
				try (AddCollector c = new AddCollector(changeListeners.fire)) {
					synchronized (lock) {
						info.trackTraceBreakpoint(breakpoint, c, false);
					}
				}
			}
		}

		private void breakpointDeleted(TraceBreakpoint breakpoint) {
			// Msg.debug(this, "Breakpoint deleted: " + breakpoint);
			if (!breakpoint.getLifespan().contains(info.recorder.getSnap())) {
				// NOTE: User/script probably removed historical breakpoint
				assert false;
				return;
			}
			try (RemoveCollector c = new RemoveCollector(changeListeners.fire)) {
				synchronized (lock) {
					info.forgetTraceBreakpoint(breakpoint, c);
				}
			}
		}
	}

	private class ProgramBreakpointsListener extends TraceDomainObjectListener {
		private final InfoPerProgram info;

		public ProgramBreakpointsListener(InfoPerProgram info) {
			this.info = info;

			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());
			listenForUntyped(ChangeManager.DOCR_BOOKMARK_ADDED,
				onBreakpoint(this::breakpointBookmarkAdded));
			listenForUntyped(ChangeManager.DOCR_BOOKMARK_CHANGED,
				onBreakpoint(this::breakpointBookmarkChanged));
			listenForUntyped(ChangeManager.DOCR_BOOKMARK_REMOVED,
				onBreakpoint(this::breakpointBookmarkDeleted));
		}

		private void objectRestored() {
			// Msg.debug(this, "Restored: " + info.program);
			synchronized (lock) {
				info.reloadBreakpoints();
				// NOTE: logical breakpoints should know which traces are affected
			}
		}

		private Consumer<DomainObjectChangeRecord> onBreakpoint(Consumer<Bookmark> handler) {
			return rec -> {
				ProgramChangeRecord pcrec = (ProgramChangeRecord) rec; // Eww
				Bookmark bm = (Bookmark) pcrec.getObject(); // So gross
				String bmType = bm.getTypeString();
				if (LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE.equals(bmType) ||
					LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE.equals(bmType)) {
					handler.accept(bm);
				}
			};
		}

		private void breakpointBookmarkAdded(Bookmark bookmark) {
			// Msg.debug(this, "Breakpoint bookmark added: " + bookmark);
			try (AddCollector c = new AddCollector(changeListeners.fire)) {
				synchronized (lock) {
					// Msg.debug(this, "Processing breakpoint bookmark add");
					info.trackProgramBreakpoint(bookmark, c);
				}
			}
		}

		private void breakpointBookmarkChanged(Bookmark bookmark) {
			synchronized (lock) {
				breakpointBookmarkDeleted(bookmark);
				breakpointBookmarkAdded(bookmark);
			}
		}

		private void breakpointBookmarkDeleted(Bookmark bookmark) {
			try (RemoveCollector c = new RemoveCollector(changeListeners.fire)) {
				synchronized (lock) {
					info.forgetProgramBreakpoint(bookmark, c);
				}
			}
		}
	}

	protected abstract class AbstractInfo {
		final NavigableMap<Address, Set<LogicalBreakpointInternal>> breakpointsByAddress =
			new TreeMap<>();

		public AbstractInfo() {
		}

		protected abstract void dispose();

		protected abstract LogicalBreakpointInternal createLogicalBreakpoint(Address address,
				long length, Collection<TraceBreakpointKind> kinds);

		protected LogicalBreakpointInternal getOrCreateLogicalBreakpointFor(Address address,
				TraceBreakpoint breakpoint, AddCollector c) {
			Set<LogicalBreakpointInternal> set =
				breakpointsByAddress.computeIfAbsent(address, a -> new HashSet<>());
			for (LogicalBreakpointInternal lb : set) {
				if (lb.canMerge(breakpoint)) {
					return lb;
				}
			}

			LogicalBreakpointInternal lb =
				createLogicalBreakpoint(address, breakpoint.getLength(), breakpoint.getKinds());
			set.add(lb);
			c.added(lb);
			return lb;
		}

		protected LogicalBreakpointInternal removeFromLogicalBreakpoint(Address address,
				TraceBreakpoint breakpoint, RemoveCollector c) {
			Set<LogicalBreakpointInternal> set = breakpointsByAddress.get(address);
			if (set == null) {
				Msg.warn(this, "Breakpoint to remove is not present: " + breakpoint + ", trace=" +
					breakpoint.getTrace());
				return null;
			}
			for (LogicalBreakpointInternal lb : Set.copyOf(set)) {
				if (lb.untrackBreakpoint(breakpoint)) {
					if (lb.isEmpty()) {
						// If being disposed, this info is no longer in the map
						removeLogicalBreakpoint(address, lb);
						removeLogicalBreakpointGlobally(lb);
						c.removed(lb);
					}
					else {
						c.updated(lb);
					}
					return lb;
				}
			}
			Msg.warn(this, "Breakpoint to remove is not present: " + breakpoint + ", trace=" +
				breakpoint.getTrace());
			return null;
		}

		protected boolean removeLogicalBreakpoint(Address address, LogicalBreakpoint lb) {
			Set<LogicalBreakpointInternal> set = breakpointsByAddress.get(address);
			if (set == null) {
				return false;
			}
			if (!set.remove(lb)) {
				return false;
			}
			if (set.isEmpty()) {
				breakpointsByAddress.remove(address);
			}
			return true;
		}

		protected boolean isMismapped(LogicalBreakpointInternal lb) {
			if (!(lb instanceof MappedLogicalBreakpoint)) {
				return false; // Can't be mis-mapped if not mapped
			}
			Set<Trace> extraneous = new HashSet<>(lb.getMappedTraces());
			extraneous.removeAll(traceInfos.keySet());
			if (!extraneous.isEmpty()) {
				return true;
			}
			for (InfoPerTrace ti : traceInfos.values()) {
				TraceLocation loc = ti.toDynamicLocation(lb.getProgramLocation());
				if (loc == null) {
					if (lb.getTraceAddress(ti.trace) != null) {
						return true;
					}
					continue;
				}
				if (!loc.getAddress().equals(lb.getTraceAddress(ti.trace))) {
					return true;
				}
			}
			return false;
		}

		protected void forgetMismappedBreakpoints(RemoveCollector c, Set<Trace> additionalTraces,
				Set<Program> additionalPrograms) {
			for (Set<LogicalBreakpointInternal> set : List.copyOf(breakpointsByAddress.values())) {
				for (LogicalBreakpointInternal lb : Set.copyOf(set)) {
					if (isMismapped(lb)) {
						removeLogicalBreakpointGlobally(lb);
						c.removed(lb);
						additionalTraces.addAll(lb.getParticipatingTraces());
					}
				}
			}
		}
	}

	protected class InfoPerTrace extends AbstractInfo {
		final TraceRecorder recorder;
		final Trace trace;
		final TraceBreakpointsListener breakpointListener;

		public InfoPerTrace(TraceRecorder recorder) {
			this.recorder = recorder;
			this.trace = recorder.getTrace();
			this.breakpointListener = new TraceBreakpointsListener(this);

			trace.addListener(breakpointListener);
		}

		@Override
		protected LogicalBreakpointInternal createLogicalBreakpoint(Address address, long length,
				Collection<TraceBreakpointKind> kinds) {
			return new LoneLogicalBreakpoint(recorder, address, length, kinds);
		}

		@Override
		protected void dispose() {
			trace.removeListener(breakpointListener);

			try (RemoveCollector r = new RemoveCollector(changeListeners.fire)) {
				forgetAllBreakpoints(r);
			}
		}

		protected void reloadBreakpoints() {
			try (AddCollector a = new AddCollector(changeListeners.fire);
					RemoveCollector r = new RemoveCollector(changeListeners.fire)) {
				forgetTraceInvalidBreakpoints(r);
				trackTraceLiveBreakpoints(a);
				a.deconflict(r);
			}
		}

		protected void forgetAllBreakpoints(RemoveCollector r) {
			Collection<TraceBreakpoint> live = new ArrayList<>();
			for (AddressRange range : trace.getBaseAddressFactory().getAddressSet()) {
				live.addAll(trace
						.getBreakpointManager()
						.getBreakpointsIntersecting(Range.singleton(recorder.getSnap()), range));
			}
			for (TraceBreakpoint b : live) {
				forgetTraceBreakpoint(b, r);
			}
		}

		protected void forgetTraceInvalidBreakpoints(RemoveCollector r) {
			// Breakpoint can become invalid because it is itself invalid (deleted)
			// Or because the mapping to static space has changed or become invalid

			for (Set<LogicalBreakpointInternal> set : List
					.copyOf(breakpointsByAddress.values())) {
				for (LogicalBreakpointInternal lb : Set.copyOf(set)) {
					for (TraceBreakpoint tb : Set.copyOf(lb.getTraceBreakpoints(trace))) {
						if (!trace.getBreakpointManager().getAllBreakpoints().contains(tb)) {
							forgetTraceBreakpoint(tb, r);
							continue;
						}
						ProgramLocation progLoc = computeStaticLocation(tb);
						if (!Objects.equals(lb.getProgramLocation(), progLoc)) {
							// NOTE: This can happen to Lone breakpoints.
							// (mis)Mapped ones should already be forgotten.
							forgetTraceBreakpoint(tb, r);
							continue;
						}
					}
				}
			}
		}

		protected void trackTraceLiveBreakpoints(AddCollector c) {
			Collection<TraceBreakpoint> live = new ArrayList<>();
			for (AddressRange range : trace.getBaseAddressFactory().getAddressSet()) {
				live.addAll(trace
						.getBreakpointManager()
						.getBreakpointsIntersecting(Range.singleton(recorder.getSnap()), range));
			}
			trackTraceBreakpoints(live, c);
		}

		protected void trackTraceBreakpoints(Collection<TraceBreakpoint> breakpoints,
				AddCollector collector) {
			for (TraceBreakpoint b : breakpoints) {
				trackTraceBreakpoint(b, collector, false);
			}
		}

		protected ProgramLocation computeStaticLocation(TraceBreakpoint breakpoint) {
			if (traceManager == null ||
				!traceManager.getOpenTraces().contains(breakpoint.getTrace())) {
				/**
				 * Mapping service will throw an exception otherwise. NB: When trace is opened,
				 * mapping service will fire events causing this service to coalesce affected
				 * breakpoints.
				 */
				return null;
			}
			return mappingService.getOpenMappedLocation(new DefaultTraceLocation(trace,
				null, Range.singleton(recorder.getSnap()), breakpoint.getMinAddress()));
		}

		protected void trackTraceBreakpoint(TraceBreakpoint breakpoint, AddCollector c,
				boolean forceUpdate) {
			Address traceAddr = breakpoint.getMinAddress();
			ProgramLocation progLoc = computeStaticLocation(breakpoint);
			LogicalBreakpointInternal lb;
			if (progLoc != null) {
				InfoPerProgram progInfo = programInfos.get(progLoc.getProgram());
				lb = progInfo
						.getOrCreateLogicalBreakpointFor(progLoc.getByteAddress(), breakpoint, c);
			}
			else {
				lb = getOrCreateLogicalBreakpointFor(traceAddr, breakpoint, c);
			}
			assert breakpointsByAddress.get(traceAddr).contains(lb);
			if (forceUpdate || lb.trackBreakpoint(breakpoint)) {
				c.updated(lb);
			}
		}

		protected void forgetTraceBreakpoint(TraceBreakpoint breakpoint, RemoveCollector c) {
			LogicalBreakpointInternal lb =
				removeFromLogicalBreakpoint(breakpoint.getMinAddress(), breakpoint, c);
			if (lb == null) {
				return; // Warnings already logged
			}
			assert lb.isEmpty() == (breakpointsByAddress
					.get(breakpoint.getMinAddress()) == null ||
				!breakpointsByAddress.get(breakpoint.getMinAddress()).contains(lb));
		}

		public TraceLocation toDynamicLocation(ProgramLocation loc) {
			return mappingService.getOpenMappedLocation(trace, loc, recorder.getSnap());
		}
	}

	protected class InfoPerProgram extends AbstractInfo {
		final Program program;
		final ProgramBreakpointsListener breakpointListener;

		public InfoPerProgram(Program program) {
			this.program = program;
			this.breakpointListener = new ProgramBreakpointsListener(this);

			program.addListener(breakpointListener);
		}

		protected void mapTraceAddresses(LogicalBreakpointInternal lb) {
			for (InfoPerTrace ti : traceInfos.values()) {
				TraceLocation loc = ti.toDynamicLocation(lb.getProgramLocation());
				if (loc == null) {
					continue;
				}
				lb.setTraceAddress(ti.recorder, loc.getAddress());
				ti.breakpointsByAddress.computeIfAbsent(loc.getAddress(), __ -> new HashSet<>())
						.add(lb);
			}
		}

		@Override
		protected LogicalBreakpointInternal createLogicalBreakpoint(Address address, long length,
				Collection<TraceBreakpointKind> kinds) {
			MappedLogicalBreakpoint lb =
				new MappedLogicalBreakpoint(program, address, length, kinds);
			mapTraceAddresses(lb);
			return lb;
		}

		protected LogicalBreakpointInternal getOrCreateLogicalBreakpointFor(Bookmark bookmark,
				AddCollector c) {
			Address address = bookmark.getAddress();
			Set<LogicalBreakpointInternal> set =
				breakpointsByAddress.computeIfAbsent(address, __ -> new HashSet<>());
			for (LogicalBreakpointInternal lb : set) {
				if (lb.canMerge(program, bookmark)) {
					return lb;
				}
			}

			LogicalBreakpointInternal lb =
				createLogicalBreakpoint(address, ProgramBreakpoint.lengthFromBookmark(bookmark),
					ProgramBreakpoint.kindsFromBookmark(bookmark));
			set.add(lb);
			c.added(lb);
			return lb;
		}

		protected LogicalBreakpointInternal removeFromLogicalBreakpoint(Bookmark bookmark,
				RemoveCollector c) {
			Address address = bookmark.getAddress();
			Set<LogicalBreakpointInternal> set = breakpointsByAddress.get(address);
			if (set == null) {
				Msg.error(this, "Breakpoint " + bookmark + " was not tracked before removal!");
				return null;
			}
			for (LogicalBreakpointInternal lb : Set.copyOf(set)) {
				if (lb.untrackBreakpoint(program, bookmark)) {
					if (lb.isEmpty()) {
						// If being disposed, this info may no longer be in the map
						removeLogicalBreakpoint(address, lb);
						removeLogicalBreakpointGlobally(lb);
						c.removed(lb);
					}
					else {
						c.updated(lb);
					}
					return lb;
				}
			}
			Msg.error(this, "Breakpoint " + bookmark + " was not tracked before removal!");
			return null;
		}

		@Override
		protected void dispose() {
			program.removeListener(breakpointListener);

			try (RemoveCollector r = new RemoveCollector(changeListeners.fire)) {
				forgetAllBreakpoints(r);
			}
		}

		protected void reloadBreakpoints() {
			try (AddCollector a = new AddCollector(changeListeners.fire);
					RemoveCollector r = new RemoveCollector(changeListeners.fire)) {
				forgetProgramInvalidBreakpoints(r);
				trackAllProgramBreakpoints(a);
				a.deconflict(r);
			}
		}

		protected void forgetAllBreakpoints(RemoveCollector r) {
			Collection<Bookmark> marks = new ArrayList<>();
			program.getBookmarkManager()
					.getBookmarksIterator(LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE)
					.forEachRemaining(marks::add);
			program.getBookmarkManager()
					.getBookmarksIterator(LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE)
					.forEachRemaining(marks::add);
			for (Bookmark bm : marks) {
				forgetProgramBreakpoint(bm, r);
			}
		}

		protected void forgetProgramInvalidBreakpoints(RemoveCollector r) {
			// Breakpoint can become invalid because it is itself invalid (deleted)
			// Or because its address moved (I think this can happen if the containing block moves)

			/**
			 * NOTE: A change in the program (other than bookmark address), should not affect the
			 * mapped trace addresses. That would require a change in the trace.
			 */
			for (Set<LogicalBreakpointInternal> set : List
					.copyOf(breakpointsByAddress.values())) {
				for (LogicalBreakpointInternal lb : Set.copyOf(set)) {
					Bookmark bm = lb.getProgramBookmark();
					if (bm == null) {
						continue;
					}
					if (bm != program.getBookmarkManager().getBookmark(bm.getId())) {
						forgetProgramBreakpoint(bm, r);
						continue;
					}
					if (!lb.getProgramLocation().getByteAddress().equals(bm.getAddress())) {
						forgetProgramBreakpoint(bm, r);
						continue;
					}
				}
			}
		}

		protected void trackAllProgramBreakpoints(AddCollector c) {
			BookmarkManager bookmarks = program.getBookmarkManager();
			trackProgramBreakpoints(IteratorUtils.asIterable(bookmarks
					.getBookmarksIterator(LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE)),
				c);
			trackProgramBreakpoints(IteratorUtils.asIterable(bookmarks
					.getBookmarksIterator(LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE)),
				c);
		}

		protected void trackProgramBreakpoints(Iterable<Bookmark> breakpoints, AddCollector c) {
			for (Bookmark b : breakpoints) {
				trackProgramBreakpoint(b, c);
			}
		}

		protected void trackProgramBreakpoint(Bookmark breakpoint, AddCollector c) {
			LogicalBreakpointInternal lb = getOrCreateLogicalBreakpointFor(breakpoint, c);
			assert breakpointsByAddress.get(breakpoint.getAddress()).contains(lb);
			if (lb.trackBreakpoint(breakpoint)) {
				c.updated(lb);
			}
		}

		protected void forgetProgramBreakpoint(Bookmark breakpoint, RemoveCollector c) {
			LogicalBreakpointInternal lb = removeFromLogicalBreakpoint(breakpoint, c);
			if (lb == null) {
				return;
			}
			assert lb.isEmpty() == (breakpointsByAddress.get(breakpoint.getAddress()) == null ||
				!breakpointsByAddress.get(breakpoint.getAddress()).contains(lb));
		}
	}

	// @AutoServiceConsumed via method
	private DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	// @AutoServiceConsumed via method
	private DebuggerStaticMappingService mappingService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final Object lock = new Object();
	private final ListenerSet<LogicalBreakpointsChangeListener> changeListeners =
		new ListenerSet<>(LogicalBreakpointsChangeListener.class);

	private final TrackRecordersListener recorderListener = new TrackRecordersListener();
	private final TrackMappingsListener mappingListener = new TrackMappingsListener();

	private final Map<Trace, InfoPerTrace> traceInfos = new HashMap<>();
	private final Map<Program, InfoPerProgram> programInfos = new HashMap<>();
	private final Collection<AbstractInfo> allInfos =
		new CatenatedCollection<>(traceInfos.values(), programInfos.values());

	public DebuggerLogicalBreakpointServicePlugin(PluginTool tool) {
		super(tool);
		this.autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);

	}

	protected void removeLogicalBreakpointGlobally(LogicalBreakpoint lb) {
		ProgramLocation pLoc = lb.getProgramLocation();
		if (pLoc != null) {
			InfoPerProgram info = programInfos.get(pLoc.getProgram());
			if (info != null) { // Maybe the program was just closed
				info.removeLogicalBreakpoint(pLoc.getByteAddress(), lb);
			}
		}
		for (Trace t : lb.getMappedTraces()) {
			Address tAddr = lb.getTraceAddress(t);
			InfoPerTrace info = traceInfos.get(t);
			if (info != null) { // Maybe the trace was just closed
				info.removeLogicalBreakpoint(tAddr, lb);
			}
		}
	}

	@AutoServiceConsumed
	private void setModelService(DebuggerModelService modelService) {
		if (this.modelService != null) {
			this.modelService.removeTraceRecordersChangedListener(recorderListener);
		}
		this.modelService = modelService;
		if (this.modelService != null) {
			this.modelService.addTraceRecordersChangedListener(recorderListener);
		}
	}

	@AutoServiceConsumed
	private void setMappingService(DebuggerStaticMappingService mappingService) {
		if (this.mappingService != null) {
			this.mappingService.removeChangeListener(mappingListener);
		}
		this.mappingService = mappingService;
		if (this.mappingService != null) {
			this.mappingService.addChangeListener(mappingListener);
		}
	}

	private void programOpened(Program program) {
		// Msg.debug(this, "Opened Program: " + program);
		synchronized (lock) {
			if (program instanceof TraceProgramView) {
				// TODO: Not a good idea for user/script, but not prohibited
				return;
			}
			InfoPerProgram info = new InfoPerProgram(program);
			if (programInfos.put(program, info) != null) {
				throw new AssertionError("Already tracking program breakpoints");
			}
			info.reloadBreakpoints();
		}
	}

	private void programClosed(Program program) {
		synchronized (lock) {
			if (program instanceof TraceProgramView) {
				return;
			}
			programInfos.remove(program).dispose();
			// The mapping removals, if applicable, will clean up related traces
		}
	}

	private void doTrackTrace(Trace trace, TraceRecorder recorder) {
		if (traceInfos.containsKey(trace)) {
			Msg.warn(this, "Already tracking trace breakpoints");
			return;
		}
		InfoPerTrace info = new InfoPerTrace(recorder);
		traceInfos.put(trace, info);
		info.reloadBreakpoints();
	}

	private void doUntrackTrace(Trace trace) {
		synchronized (lock) {
			InfoPerTrace info = traceInfos.remove(trace);
			if (info != null) { // Could be from trace close or recorder stop
				info.dispose();
			}
		}
	}

	private void traceRecordingStarted(TraceRecorder recorder) {
		synchronized (lock) {
			Trace trace = recorder.getTrace();
			if (!traceManager.getOpenTraces().contains(trace)) {
				return;
			}
			doTrackTrace(trace, recorder);
		}
	}

	private void traceRecordingStopped(TraceRecorder recorder) {
		doUntrackTrace(recorder.getTrace());
	}

	private void traceOpened(Trace trace) {
		synchronized (lock) {
			TraceRecorder recorder = modelService.getRecorder(trace);
			if (recorder == null) {
				return;
			}
			doTrackTrace(trace, recorder);
		}
	}

	private void traceClosed(Trace trace) {
		doUntrackTrace(trace);
	}

	@Override
	public Set<LogicalBreakpoint> getAllBreakpoints() {
		// TODO: Could probably track this set
		synchronized (lock) {
			Set<LogicalBreakpoint> records = new HashSet<>();
			for (AbstractInfo info : allInfos) {
				for (Set<LogicalBreakpointInternal> recsAtAddress : info.breakpointsByAddress
						.values()) {
					records.addAll(recsAtAddress);
				}
			}
			return records;
		}
	}

	protected static <K, V> NavigableMap<K, Set<V>> copyOf(
			NavigableMap<? extends K, ? extends Set<? extends V>> map) {
		NavigableMap<K, Set<V>> result = new TreeMap<>();
		for (Map.Entry<? extends K, ? extends Set<? extends V>> ent : map.entrySet()) {
			result.put(ent.getKey(), new HashSet<>(ent.getValue()));
		}
		return result;
	}

	@Override
	public NavigableMap<Address, Set<LogicalBreakpoint>> getBreakpoints(Program program) {
		synchronized (lock) {
			InfoPerProgram info = programInfos.get(program);
			if (info == null) {
				return Collections.emptyNavigableMap();
			}
			return copyOf(info.breakpointsByAddress);
		}
	}

	@Override
	public NavigableMap<Address, Set<LogicalBreakpoint>> getBreakpoints(Trace trace) {
		synchronized (lock) {
			InfoPerTrace info = traceInfos.get(trace);
			if (info == null) {
				return Collections.emptyNavigableMap();
			}
			return copyOf(info.breakpointsByAddress);
		}
	}

	protected Set<LogicalBreakpoint> doGetBreakpointsAt(AbstractInfo info, Address address) {
		Set<LogicalBreakpointInternal> set = info.breakpointsByAddress.get(address);
		if (set == null) {
			return Set.of();
		}
		return new HashSet<>(set);
	}

	@Override
	public Set<LogicalBreakpoint> getBreakpointsAt(Program program, Address address) {
		synchronized (lock) {
			InfoPerProgram info = programInfos.get(program);
			if (info == null) {
				return Set.of();
			}
			return doGetBreakpointsAt(info, address);
		}
	}

	@Override
	public Set<LogicalBreakpoint> getBreakpointsAt(Trace trace, Address address) {
		synchronized (lock) {
			InfoPerTrace info = traceInfos.get(trace);
			if (info == null) {
				return Set.of();
			}
			return doGetBreakpointsAt(info, address);
		}
	}

	@Override
	public Set<LogicalBreakpoint> getBreakpointsAt(ProgramLocation loc) {
		return DebuggerLogicalBreakpointService.programOrTrace(loc,
			this::getBreakpointsAt,
			this::getBreakpointsAt);
	}

	@Override
	public void addChangeListener(LogicalBreakpointsChangeListener l) {
		changeListeners.add(l);
	}

	@Override
	public void removeChangeListener(LogicalBreakpointsChangeListener l) {
		changeListeners.remove(l);
	}

	@Override
	public CompletableFuture<Void> placeBreakpointAt(Program program, Address address, long length,
			Collection<TraceBreakpointKind> kinds) {
		/**
		 * TODO: This is quite a waste, but it gets the job done. The instance created here is
		 * dropped. It's just used for its breakpoint placement logic, part of which I had to
		 * re-implement here, anyway. The actual logical breakpoint is created by event processors.
		 */
		MappedLogicalBreakpoint lb = new MappedLogicalBreakpoint(program, address, length, kinds);
		synchronized (lock) {
			for (InfoPerTrace ti : traceInfos.values()) {
				TraceLocation loc = ti.toDynamicLocation(lb.getProgramLocation());
				if (loc == null) {
					continue;
				}
				lb.setTraceAddress(ti.recorder, loc.getAddress());
			}
		}
		return lb.enable();
	}

	@Override
	public CompletableFuture<Void> placeBreakpointAt(Trace trace, Address address, long length,
			Collection<TraceBreakpointKind> kinds) {
		TraceRecorder recorder = modelService.getRecorder(trace);
		if (recorder == null) {
			throw new IllegalArgumentException("Given trace is not live");
		}
		/**
		 * TODO: This is similarly wasteful, but given the complexity of the breakpoint placement
		 * logic it offers, this works really well, and is probably justified.
		 */
		return new LoneLogicalBreakpoint(recorder, address, length, kinds).enableForTrace(trace);
	}

	@Override
	public CompletableFuture<Void> placeBreakpointAt(ProgramLocation loc, long length,
			Collection<TraceBreakpointKind> kinds) {
		return DebuggerLogicalBreakpointService.programOrTrace(loc,
			(p, a) -> placeBreakpointAt(p, a, length, kinds),
			(t, a) -> placeBreakpointAt(t, a, length, kinds));
	}

	protected CompletableFuture<Void> actOnAll(Collection<LogicalBreakpoint> col, Trace trace,
			Consumer<LogicalBreakpoint> consumerForProgram,
			BiConsumer<BreakpointActionSet, LogicalBreakpointInternal> consumerForTarget) {
		BreakpointActionSet actions = new BreakpointActionSet();
		for (LogicalBreakpoint lb : col) {
			if (trace == null) {
				consumerForProgram.accept(lb);
			}
			if (!(lb instanceof LogicalBreakpointInternal)) {
				continue;
			}
			LogicalBreakpointInternal lbi = (LogicalBreakpointInternal) lb;
			consumerForTarget.accept(actions, lbi);
		}
		return actions.execute();
	}

	@Override
	public CompletableFuture<Void> enableAll(Collection<LogicalBreakpoint> col, Trace trace) {
		return actOnAll(col, trace, LogicalBreakpoint::enableForProgram,
			(actions, lbi) -> lbi.planEnable(actions, trace));
	}

	@Override
	public CompletableFuture<Void> disableAll(Collection<LogicalBreakpoint> col, Trace trace) {
		return actOnAll(col, trace, LogicalBreakpoint::disableForProgram,
			(actions, lbi) -> lbi.planDisable(actions, trace));
	}

	@Override
	public CompletableFuture<Void> deleteAll(Collection<LogicalBreakpoint> col, Trace trace) {
		return actOnAll(col, trace, LogicalBreakpoint::deleteForProgram,
			(actions, lbi) -> lbi.planDelete(actions, trace));
	}

	protected CompletableFuture<Void> actOnLocs(Collection<TraceBreakpoint> col,
			BiConsumer<BreakpointActionSet, TargetBreakpointLocation> consumer) {
		BreakpointActionSet actions = new BreakpointActionSet();
		for (TraceBreakpoint tb : col) {
			TraceRecorder recorder = modelService.getRecorder(tb.getTrace());
			if (recorder == null) {
				continue;
			}
			List<String> path = PathUtils.parse(tb.getPath());
			TargetObject object = recorder.getTarget().getModel().getModelObject(path);
			if (!(object instanceof TargetBreakpointLocation)) {
				Msg.error(this, tb.getPath() + " is not a target breakpoint location");
				continue;
			}
			TargetBreakpointLocation loc = (TargetBreakpointLocation) object;
			consumer.accept(actions, loc);
		}
		return actions.execute();
	}

	@Override
	public CompletableFuture<Void> enableLocs(Collection<TraceBreakpoint> col) {
		return actOnLocs(col, BreakpointActionSet::planEnable);
	}

	@Override
	public CompletableFuture<Void> disableLocs(Collection<TraceBreakpoint> col) {
		return actOnLocs(col, BreakpointActionSet::planDisable);
	}

	@Override
	public CompletableFuture<Void> deleteLocs(Collection<TraceBreakpoint> col) {
		return actOnLocs(col, BreakpointActionSet::planDelete);
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramOpenedPluginEvent) {
			ProgramOpenedPluginEvent openedEvt = (ProgramOpenedPluginEvent) event;
			programOpened(openedEvt.getProgram());
		}
		else if (event instanceof ProgramClosedPluginEvent) {
			ProgramClosedPluginEvent closedEvt = (ProgramClosedPluginEvent) event;
			programClosed(closedEvt.getProgram());
		}
		else if (event instanceof TraceOpenedPluginEvent) {
			TraceOpenedPluginEvent openedEvt = (TraceOpenedPluginEvent) event;
			traceOpened(openedEvt.getTrace());
		}
		else if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent closedEvt = (TraceClosedPluginEvent) event;
			traceClosed(closedEvt.getTrace());
		}
	}
}
