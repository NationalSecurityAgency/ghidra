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
package ghidra.app.plugin.core.debug.service.modules;

import java.net.URL;
import java.util.*;
import java.util.concurrent.Executor;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.utils.ProgramLocationUtils;
import ghidra.async.AsyncUtils;
import ghidra.debug.api.modules.DebuggerStaticMappingChangeListener;
import ghidra.debug.api.modules.MappedAddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;

public class DebuggerStaticMappingContext {

	record ChangeCollector(DebuggerStaticMappingContext ctx, Set<Trace> traces,
			Set<Program> programs) implements AutoCloseable {

		static <T> Set<T> subtract(Set<T> a, Set<T> b) {
			Set<T> result = new HashSet<>(a);
			result.removeAll(b);
			return result;
		}

		public ChangeCollector(DebuggerStaticMappingContext ctx) {
			this(ctx, new HashSet<>(), new HashSet<>());
		}

		public void traceAffected(Trace trace) {
			this.traces.add(trace);
		}

		public void programAffected(Program program) {
			if (program != null) {
				this.programs.add(program);
			}
		}

		@Override
		public void close() {
			ctx.changeListeners.getProxy().mappingsChanged(traces, programs);
		}
	}

	final Map<Trace, InfoPerTrace> traceInfoByTrace = new HashMap<>();
	final Map<Program, InfoPerProgram> programInfoByProgram = new HashMap<>();
	final Map<URL, InfoPerProgram> programInfoByUrl = new HashMap<>();

	final Object lock = new Object();

	final Executor executor;
	private final ListenerSet<DebuggerStaticMappingChangeListener> changeListeners =
		new ListenerSet<>(DebuggerStaticMappingChangeListener.class, true);

	public DebuggerStaticMappingContext() {
		this(AsyncUtils.DIRECT_EXECUTOR);
	}

	public DebuggerStaticMappingContext(Executor executor) {
		this.executor = executor;
	}

	public void addChangeListener(DebuggerStaticMappingChangeListener l) {
		changeListeners.add(l);
	}

	public void removeChangeListener(DebuggerStaticMappingChangeListener l) {
		changeListeners.remove(l);
	}

	public ChangeCollector collectChanges() {
		return new ChangeCollector(this);
	}

	public void addProgram(ChangeCollector cc, Program program) {
		synchronized (lock) {
			processAddedProgram(cc, program);
		}
	}

	public void removeProgram(ChangeCollector cc, Program program) {
		synchronized (lock) {
			processRemovedProgramInfo(cc, requireTrackedInfo(program));
		}
	}

	public void setPrograms(ChangeCollector cc, Set<Program> programs) {
		synchronized (lock) {
			Set<InfoPerProgram> removed = programInfoByProgram.values()
					.stream()
					.filter(i -> !programs.contains(i.program) || !i.urlMatches())
					.collect(Collectors.toSet());
			processRemovedProgramInfos(cc, removed);
			Set<Program> added = ChangeCollector.subtract(programs, programInfoByProgram.keySet());
			processAddedPrograms(cc, added);
		}
	}

	public void addTrace(ChangeCollector cc, Trace trace) {
		synchronized (lock) {
			processAddedTrace(cc, trace);
		}
	}

	public void removeTrace(ChangeCollector cc, Trace trace) {
		synchronized (lock) {
			processRemovedTrace(cc, trace);
		}
	}

	public void setTraces(ChangeCollector cc, Set<Trace> traces) {
		synchronized (lock) {
			Set<Trace> oldTraces = traceInfoByTrace.keySet();

			Set<Trace> removed = ChangeCollector.subtract(oldTraces, traces);
			Set<Trace> added = ChangeCollector.subtract(traces, oldTraces);

			processRemovedTraces(cc, removed);
			processAddedTraces(cc, added);
		}
	}

	protected <T> T noTraceInfo() {
		Msg.debug(this, "The given trace is not open in this tool " +
			"(or the service hasn't received and processed the open-trace event, yet)");
		return null;
	}

	protected <T> T noProgramInfo() {
		Msg.debug(this, "The given program is not open in this tool " +
			"(or the service hasn't received and processed the open-program event, yet)");
		return null;
	}

	protected <T> T noProject() {
		return DebuggerStaticMappingUtils.noProject(this);
	}

	void checkAndClearProgram(ChangeCollector cc, MappingEntry me) {
		InfoPerProgram info = programInfoByUrl.get(me.getStaticProgramUrl());
		if (info == null) {
			return;
		}
		info.clearProgram(cc, me);
	}

	void checkAndFillProgram(ChangeCollector cc, MappingEntry me) {
		InfoPerProgram info = programInfoByUrl.get(me.getStaticProgramUrl());
		if (info == null) {
			return;
		}
		info.fillProgram(cc, me);
	}

	void processRemovedProgramInfos(ChangeCollector cc, Set<InfoPerProgram> removed) {
		for (InfoPerProgram info : removed) {
			processRemovedProgramInfo(cc, info);
		}
	}

	void processRemovedProgramInfo(ChangeCollector cc, InfoPerProgram info) {
		programInfoByProgram.remove(info.program);
		programInfoByUrl.remove(info.url);
		info.clearEntries(cc);
	}

	void processAddedPrograms(ChangeCollector cc, Set<Program> added) {
		for (Program program : added) {
			processAddedProgram(cc, program);
		}
	}

	void processAddedProgram(ChangeCollector cc, Program program) {
		InfoPerProgram info = new InfoPerProgram(this, program);
		programInfoByProgram.put(program, info);
		programInfoByUrl.put(info.url, info);
		info.fillEntries(cc);
	}

	void processRemovedTraces(ChangeCollector cc, Set<Trace> removed) {
		for (Trace trace : removed) {
			processRemovedTrace(cc, trace);
		}
	}

	void processRemovedTrace(ChangeCollector cc, Trace trace) {
		InfoPerTrace info = traceInfoByTrace.remove(trace);
		info.removeEntries(cc);
	}

	void processAddedTraces(ChangeCollector cc, Set<Trace> added) {
		for (Trace trace : added) {
			processAddedTrace(cc, trace);
		}
	}

	void processAddedTrace(ChangeCollector cc, Trace trace) {
		InfoPerTrace info = new InfoPerTrace(this, trace);
		traceInfoByTrace.put(trace, info);
		info.resyncEntries(cc);
	}

	protected InfoPerTrace requireTrackedInfo(Trace trace) {
		InfoPerTrace info = traceInfoByTrace.get(trace);
		if (info == null) {
			return noTraceInfo();
		}
		return info;
	}

	protected InfoPerProgram requireTrackedInfo(Program program) {
		InfoPerProgram info = programInfoByProgram.get(program);
		if (info == null) {
			return noProgramInfo();
		}
		return info;
	}

	public Set<Program> getOpenMappedProgramsAtSnap(Trace trace, long snap) {
		synchronized (lock) {
			InfoPerTrace info = requireTrackedInfo(trace);
			if (info == null) {
				return null;
			}
			return info.getOpenMappedProgramsAtSnap(snap);
		}
	}

	public ProgramLocation getOpenMappedLocation(TraceLocation loc) {
		synchronized (lock) {
			InfoPerTrace info = requireTrackedInfo(loc.getTrace());
			if (info == null) {
				return null;
			}
			return info.getOpenMappedProgramLocation(loc.getAddress(), loc.getLifespan());
		}
	}

	protected long getNonScratchSnap(TraceProgramView view) {
		return view.getViewport().getTop(s -> s >= 0 ? s : null);
	}

	public ProgramLocation getStaticLocationFromDynamic(ProgramLocation loc) {
		synchronized (lock) {
			loc = ProgramLocationUtils.fixLocation(loc, true);
			TraceProgramView view = (TraceProgramView) loc.getProgram();
			Trace trace = view.getTrace();
			TraceLocation tloc = new DefaultTraceLocation(trace, null,
				Lifespan.at(getNonScratchSnap(view)), loc.getByteAddress());
			ProgramLocation mapped = getOpenMappedLocation(tloc);
			if (mapped == null) {
				return null;
			}
			return ProgramLocationUtils.replaceAddress(loc, mapped.getProgram(),
				mapped.getByteAddress());
		}
	}

	public Set<TraceLocation> getOpenMappedLocations(ProgramLocation loc) {
		synchronized (lock) {
			InfoPerProgram info = requireTrackedInfo(loc.getProgram());
			if (info == null) {
				return null;
			}
			return info.getOpenMappedTraceLocations(loc.getByteAddress());
		}
	}

	public TraceLocation getOpenMappedLocation(Trace trace, ProgramLocation loc, long snap) {
		synchronized (lock) {
			InfoPerProgram info = requireTrackedInfo(loc.getProgram());
			if (info == null) {
				return null;
			}
			return info.getOpenMappedTraceLocation(trace, loc.getByteAddress(), snap);
		}
	}

	public ProgramLocation getDynamicLocationFromStatic(TraceProgramView view,
			ProgramLocation loc) {
		synchronized (lock) {
			TraceLocation tloc =
				getOpenMappedLocation(view.getTrace(), loc, getNonScratchSnap(view));
			if (tloc == null) {
				return null;
			}
			return ProgramLocationUtils.replaceAddress(loc, view, tloc.getAddress());
		}
	}

	public Map<Program, Collection<MappedAddressRange>> getOpenMappedViews(Trace trace,
			AddressSetView set, long snap) {
		synchronized (lock) {
			InfoPerTrace info = requireTrackedInfo(trace);
			if (info == null) {
				return Map.of();
			}
			return info.getOpenMappedViews(set, Lifespan.at(snap));
		}
	}

	public Map<TraceSpan, Collection<MappedAddressRange>> getOpenMappedViews(Program program,
			AddressSetView set) {
		synchronized (lock) {
			InfoPerProgram info = requireTrackedInfo(program);
			if (info == null) {
				return Map.of();
			}
			return info.getOpenMappedViews(set);
		}
	}

	public Set<URL> getMappedProgramUrlsInView(Trace trace, AddressSetView set, long snap) {
		synchronized (lock) {
			InfoPerTrace info = requireTrackedInfo(trace);
			if (info == null) {
				return null;
			}
			return info.getMappedProgramUrlsInView(set, Lifespan.at(snap));
		}
	}
}
