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
package ghidra.app.plugin.core.debug;

import java.io.IOException;
import java.util.Objects;

import org.jdom.Element;

import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.TraceRecorder;
import ghidra.framework.data.ProjectFileManager;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.database.DBTraceContentHandler;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.NotOwnerException;

public class DebuggerCoordinates {
	public static final DebuggerCoordinates NOWHERE =
		new DebuggerCoordinates(null, null, null, null, 0L, "", 0) {
			@Override
			public void writeDataState(PluginTool tool, SaveState saveState, String key) {
				// Write nothing
			}
		};

	private static final String KEY_TRACE_PROJ_LOC = "TraceProjLoc";
	private static final String KEY_TRACE_PROJ_NAME = "TraceProjName";
	private static final String KEY_TRACE_PATH = "TracePath";
	private static final String KEY_TRACE_VERSION = "TraceVersion";
	private static final String KEY_THREAD_KEY = "ThreadKey";
	private static final String KEY_SNAP = "Snap";
	private static final String KEY_TICKS = "Ticks";
	private static final String KEY_FRAME = "Frame";

	public static DebuggerCoordinates all(Trace trace, TraceRecorder recorder, TraceThread thread,
			TraceProgramView view, Long snap, String ticks, Integer frame) {
		if (trace == NOWHERE.trace && recorder == NOWHERE.recorder && thread == NOWHERE.thread &&
			view == NOWHERE.view && snap == NOWHERE.snap && ticks == NOWHERE.ticks &&
			frame == NOWHERE.frame) {
			return NOWHERE;
		}
		return new DebuggerCoordinates(trace, recorder, thread, view, snap, ticks, frame);
	}

	public static DebuggerCoordinates trace(Trace trace) {
		if (trace == null) {
			return NOWHERE;
		}
		return all(trace, null, null, null, null, null, null);
	}

	public static DebuggerCoordinates recorder(TraceRecorder recorder) {
		return all(recorder == null ? null : recorder.getTrace(), recorder,
			null, null, recorder == null ? null : recorder.getSnap(), null, null);
	}

	public static DebuggerCoordinates thread(TraceThread thread) {
		return all(thread == null ? null : thread.getTrace(), null, thread,
			null, null, null, null);
	}

	public static DebuggerCoordinates view(TraceProgramView view) {
		return all(view == null ? null : view.getTrace(), null, null, view,
			view == null ? null : view.getSnap(), null, null);
	}

	public static DebuggerCoordinates snap(long snap) {
		return all(null, null, null, null, snap, null, null);
	}

	public static DebuggerCoordinates frame(int frame) {
		return all(null, null, null, null, null, null, frame);
	}

	public static DebuggerCoordinates threadSnap(TraceThread thread, long snap) {
		return all(thread == null ? null : thread.getTrace(), null, thread, null, snap, null, null);
	}

	public static boolean equalsIgnoreRecorderAndView(DebuggerCoordinates a,
			DebuggerCoordinates b) {
		if (!Objects.equals(a.trace, b.trace)) {
			return false;
		}
		if (!Objects.equals(a.thread, b.thread)) {
			return false;
		}
		if (!Objects.equals(a.snap, b.snap)) {
			return false;
		}
		if (!Objects.equals(a.ticks, b.ticks)) {
			return false;
		}
		if (!Objects.equals(a.frame, b.frame)) {
			return false;
		}
		return true;
	}

	private final Trace trace;
	private final TraceRecorder recorder;
	private final TraceThread thread;
	private final TraceProgramView view;
	private final Long snap;
	private final String ticks;
	private final Integer frame;

	private final int hash;

	protected DebuggerCoordinates(Trace trace, TraceRecorder recorder, TraceThread thread,
			TraceProgramView view, Long snap, String ticks, Integer frame) {
		this.trace = trace;
		this.recorder = recorder;
		this.thread = thread;
		this.view = view;
		this.snap = snap;
		this.ticks = ticks;
		this.frame = frame;

		this.hash = Objects.hash(trace, recorder, thread, view, snap, ticks, frame);
	}

	@Override
	public String toString() {
		return String.format(
			"Coords(trace=%s,recorder=%s,thread=%s,view=%s,snap=%d,ticks=%s,frame=%d)",
			trace, recorder, thread, view, snap, ticks, frame);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof DebuggerCoordinates)) {
			return false;
		}
		DebuggerCoordinates that = (DebuggerCoordinates) obj;
		if (!Objects.equals(this.trace, that.trace)) {
			return false;
		}
		if (!Objects.equals(this.recorder, that.recorder)) {
			return false;
		}
		if (!Objects.equals(this.thread, that.thread)) {
			return false;
		}
		if (!Objects.equals(this.view, that.view)) {
			return false;
		}
		if (!Objects.equals(this.snap, that.snap)) {
			return false;
		}
		if (!Objects.equals(this.ticks, that.ticks)) {
			return false;
		}
		if (!Objects.equals(this.frame, that.frame)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return hash;
	}

	public Trace getTrace() {
		return trace;
	}

	public TraceRecorder getRecorder() {
		return recorder;
	}

	public DebuggerCoordinates withRecorder(TraceRecorder newRecorder) {
		return all(trace, newRecorder, thread, view, snap, ticks, frame);
	}

	public TraceThread getThread() {
		return thread;
	}

	public DebuggerCoordinates withReFoundThread() {
		if (trace == null || thread == null) {
			return this;
		}
		TraceThread newThread = trace.getThreadManager().getThread(thread.getKey());
		if (thread == newThread) {
			return this;
		}
		return withThread(newThread);
	}

	public DebuggerCoordinates withThread(TraceThread newThread) {
		return all(trace, recorder, newThread, view, snap, ticks, frame);
	}

	public TraceProgramView getView() {
		return view;
	}

	public Long getSnap() {
		return snap;
	}

	public DebuggerCoordinates withSnap(Long newSnap) {
		return all(trace, recorder, thread, view, newSnap, ticks, frame);
	}

	public String getTicks() {
		return ticks;
	}

	public Integer getFrame() {
		return frame;
	}

	public void writeDataState(PluginTool tool, SaveState saveState, String key) {
		SaveState coordState = new SaveState();
		// for NOWHERE, key should be completely omitted
		if (trace != null) {
			DomainFile df = trace.getDomainFile();
			if (df.getParent() == null) {
				return; // not contained within any project
			}
			ProjectLocator projLoc = df.getProjectLocator();
			if (projLoc != null && !projLoc.isTransient()) {
				coordState.putString(KEY_TRACE_PROJ_LOC, projLoc.getLocation());
				coordState.putString(KEY_TRACE_PROJ_NAME, projLoc.getName());
				coordState.putString(KEY_TRACE_PATH, df.getPathname());
				if (!df.isLatestVersion()) {
					coordState.putInt(KEY_TRACE_VERSION, df.getVersion());
				}
			}
		}
		if (thread != null) {
			coordState.putLong(KEY_THREAD_KEY, thread.getKey());
		}
		if (snap != null) {
			coordState.putLong(KEY_SNAP, snap);
		}
		if (ticks != null) {
			coordState.putString(KEY_TICKS, ticks);
		}
		if (frame != null) {
			coordState.putInt(KEY_FRAME, frame);
		}

		saveState.putXmlElement(key, coordState.saveToXml());
	}

	protected static DomainFile getDomainFile(PluginTool tool, SaveState coordState) {
		String pathname = coordState.getString(KEY_TRACE_PATH, null);
		String location = coordState.getString(KEY_TRACE_PROJ_LOC, null);
		String projName = coordState.getString(KEY_TRACE_PROJ_NAME, null);
		if (location == null || projName == null) {
			return null;
		}
		ProjectLocator projLoc = new ProjectLocator(location, projName);

		ProjectData projData = tool.getProject().getProjectData(projLoc);
		if (projData == null) {
			try {
				projData = new ProjectFileManager(projLoc, false, false);
			}
			catch (NotOwnerException e) {
				Msg.showError(DebuggerCoordinates.class, tool.getToolFrame(), "Trace Open Failed",
					"Not project owner: " + projLoc + "(" + pathname + ")");
				return null;
			}
			catch (IOException e) {
				Msg.showError(DebuggerCoordinates.class, tool.getToolFrame(), "Trace Open Failed",
					"Project error: " + e.getMessage());
				return null;
			}
		}

		DomainFile df = projData.getFile(pathname);
		if (df == null || !DBTraceContentHandler.TRACE_CONTENT_TYPE.equals(df.getContentType())) {
			String message = "Can't open trace - \"" + pathname + "\"";
			int version = coordState.getInt(KEY_TRACE_VERSION, DomainFile.DEFAULT_VERSION);
			if (version != DomainFile.DEFAULT_VERSION) {
				message += " version " + version;
			}
			String title = df == null ? "Trace Not Found" : "Wrong File Type";
			Msg.showError(DebuggerCoordinates.class, tool.getToolFrame(), title, message);
			return null;
		}
		return df;
	}

	public static DebuggerCoordinates readDataState(PluginTool tool, SaveState saveState,
			String key, boolean resolve) {
		if (!saveState.hasValue(key)) {
			return NOWHERE;
		}
		DebuggerTraceManagerService traceManager =
			tool.getService(DebuggerTraceManagerService.class);
		Trace trace = null;
		Element coordElement = saveState.getXmlElement(key);
		SaveState coordState = new SaveState(coordElement);
		if (traceManager != null) {
			DomainFile df = getDomainFile(tool, coordState);
			int version = coordState.getInt(KEY_TRACE_VERSION, DomainFile.DEFAULT_VERSION);
			if (df != null) {
				trace = traceManager.openTrace(df, version);
			}
		}
		TraceThread thread = null;
		if (trace != null && coordState.hasValue(KEY_THREAD_KEY)) {
			long threadKey = coordState.getLong(KEY_THREAD_KEY, 0);
			thread = trace.getThreadManager().getThread(threadKey);
		}
		Long snap = null;
		if (coordState.hasValue(KEY_SNAP)) {
			snap = coordState.getLong(KEY_SNAP, 0);
		}
		String ticks = coordState.getString(KEY_TICKS, null);
		Integer frame = null;
		if (coordState.hasValue(KEY_FRAME)) {
			frame = coordState.getInt(KEY_FRAME, 0);
		}

		DebuggerCoordinates coords =
			DebuggerCoordinates.all(trace, null, thread, null, snap, ticks, frame);
		if (!resolve) {
			return coords;
		}
		return traceManager.resolveCoordinates(coords);
	}

	public boolean isDeadOrPresent() {
		return recorder == null || isPresent();
	}

	public boolean isAlive() {
		return recorder != null;
	}

	public boolean isPresent() {
		return recorder.getSnap() == snap;
	}

	public boolean isAliveAndPresent() {
		return isAlive() && isPresent();
	}
}
