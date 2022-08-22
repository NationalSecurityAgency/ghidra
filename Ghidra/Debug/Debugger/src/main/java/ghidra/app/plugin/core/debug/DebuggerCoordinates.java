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
import java.util.Collection;
import java.util.Objects;

import org.jdom.Element;

import com.google.common.collect.Range;

import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.target.TargetObject;
import ghidra.framework.data.ProjectFileManager;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.database.DBTraceContentHandler;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.stack.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.trace.util.DefaultTraceTimeViewport;
import ghidra.trace.util.TraceTimeViewport;
import ghidra.util.Msg;
import ghidra.util.NotOwnerException;

public class DebuggerCoordinates {

	public static final DebuggerCoordinates NOWHERE =
		new DebuggerCoordinates(null, null, null, null, null, null, null);

	private static final String KEY_TRACE_PROJ_LOC = "TraceProjLoc";
	private static final String KEY_TRACE_PROJ_NAME = "TraceProjName";
	private static final String KEY_TRACE_PATH = "TracePath";
	private static final String KEY_TRACE_VERSION = "TraceVersion";
	private static final String KEY_THREAD_KEY = "ThreadKey";
	private static final String KEY_TIME = "Time";
	private static final String KEY_FRAME = "Frame";
	private static final String KEY_OBJ_PATH = "ObjectPath";

	public static boolean equalsIgnoreRecorderAndView(DebuggerCoordinates a,
			DebuggerCoordinates b) {
		if (!Objects.equals(a.trace, b.trace)) {
			return false;
		}
		if (!Objects.equals(a.thread, b.thread)) {
			return false;
		}
		// Consider defaults
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		if (!Objects.equals(a.getFrame(), b.getFrame())) {
			return false;
		}
		if (!Objects.equals(a.getObject(), b.getObject())) {
			return false;
		}
		return true;
	}

	private final Trace trace;
	private final TraceRecorder recorder;
	private final TraceThread thread;
	private final TraceProgramView view;
	private final TraceSchedule time;
	private final Integer frame;
	private final TraceObject object;

	private final int hash;

	private Long viewSnap;
	private DefaultTraceTimeViewport viewport;

	DebuggerCoordinates(Trace trace, TraceRecorder recorder, TraceThread thread,
			TraceProgramView view, TraceSchedule time, Integer frame, TraceObject object) {
		this.trace = trace;
		this.recorder = recorder;
		this.thread = thread;
		this.view = view;
		this.time = time;
		this.frame = frame;
		this.object = object;

		this.hash = Objects.hash(trace, recorder, thread, view, time, frame, object);
	}

	@Override
	public String toString() {
		return String.format(
			"Coords(trace=%s,recorder=%s,thread=%s,view=%s,time=%s,frame=%d,object=%s)",
			trace, recorder, thread, view, time, frame, object);
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
		// Do not consider defaults
		if (!Objects.equals(this.time, that.time)) {
			return false;
		}
		if (!Objects.equals(this.frame, that.frame)) {
			return false;
		}
		if (!Objects.equals(this.object, that.object)) {
			return false;
		}

		return true;
	}

	@Override
	public int hashCode() {
		return hash;
	}

	private static TraceThread resolveThread(Trace trace, TraceSchedule time) {
		long snap = time.getSnap();
		return trace.getThreadManager()
				.getLiveThreads(snap)
				.stream()
				.findFirst()
				.orElse(null);
	}

	private static TraceThread resolveThread(Trace trace) {
		return resolveThread(trace, TraceSchedule.ZERO);
	}

	private static TraceObject resolveObject(Trace trace) {
		return trace.getObjectManager().getRootObject();
	}

	private static TraceProgramView resolveView(Trace trace, TraceSchedule time) {
		// TODO: Allow multiple times viewed of the same trace? (Aside from snap compare)
		// Trace manager will adjust the view's snap to match coordinates
		return trace.getProgramView();
	}

	private static TraceProgramView resolveView(Trace trace) {
		return resolveView(trace, TraceSchedule.ZERO);
	}

	public DebuggerCoordinates trace(Trace newTrace) {
		if (newTrace == null) {
			return NOWHERE;
		}
		if (trace == newTrace) {
			return this;
		}
		if (trace == null) {
			TraceThread newThread = resolveThread(newTrace);
			TraceProgramView newView = resolveView(newTrace);
			TraceSchedule newTime = null; // Allow later resolution
			Integer newFrame = resolveFrame(newThread, newTime);
			TraceObject newObject = resolveObject(newTrace);
			return new DebuggerCoordinates(newTrace, null, newThread, newView, newTime, newFrame,
				newObject);
		}
		throw new IllegalArgumentException("Cannot change trace");
	}

	private static TraceThread resolveThread(TraceRecorder recorder, TraceSchedule time) {
		if (recorder.getSnap() != time.getSnap() || !recorder.isSupportsFocus()) {
			return resolveThread(recorder.getTrace(), time);
		}
		return resolveThread(recorder, recorder.getFocus());
	}

	private static TraceThread resolveThread(Trace trace, TraceRecorder recorder,
			TraceSchedule time) {
		if (recorder == null) {
			return resolveThread(trace, time);
		}
		return resolveThread(recorder, time);
	}

	private static Integer resolveFrame(TraceThread thread, TraceSchedule time) {
		// Use null to allow later resolution. Getter will default to 0
		return null;
	}

	private static Integer resolveFrame(TraceRecorder recorder, TraceThread thread,
			TraceSchedule time) {
		if (recorder == null || recorder.getSnap() != time.getSnap() ||
			!recorder.isSupportsFocus()) {
			return resolveFrame(thread, time);
		}
		return resolveFrame(recorder, recorder.getFocus());
	}

	private static TraceObject resolveObject(Trace trace, TargetObject object) {
		if (object == null) {
			return null;
		}
		return trace.getObjectManager()
				.getObjectByCanonicalPath(TraceObjectKeyPath.of(object.getPath()));
	}

	private static TraceObject resolveObject(TraceRecorder recorder, TraceSchedule time) {
		if (recorder.getSnap() != time.getSnap() || !recorder.isSupportsFocus()) {
			return resolveObject(recorder.getTrace());
		}
		return resolveObject(recorder.getTrace(), recorder.getFocus());
	}

	public DebuggerCoordinates recorder(TraceRecorder newRecorder) {
		if (recorder == newRecorder) {
			return this;
		}
		if (newRecorder == null) {
			return new DebuggerCoordinates(trace, newRecorder, thread, view, time, frame, object);
		}
		if (newRecorder != null && trace != null && newRecorder.getTrace() != trace) {
			throw new IllegalArgumentException("Cannot change trace");
		}
		Trace newTrace = trace != null ? trace : newRecorder.getTrace();
		TraceSchedule newTime = time != null ? time : TraceSchedule.snap(newRecorder.getSnap());
		TraceThread newThread = thread != null ? thread : resolveThread(newRecorder, newTime);
		TraceProgramView newView = view != null ? view : resolveView(newTrace, newTime);
		Integer newFrame = frame != null ? frame : resolveFrame(newRecorder, newThread, newTime);
		TraceObject newObject = object != null ? object : resolveObject(newRecorder, newTime);
		return new DebuggerCoordinates(newTrace, newRecorder, newThread, newView, newTime, newFrame,
			newObject);
	}

	public DebuggerCoordinates reFindThread() {
		if (trace == null || thread == null) {
			return this;
		}
		return thread(trace.getThreadManager().getThread(thread.getKey()));
	}

	private static TraceObject resolveObject(TraceThread thread, Integer frameLevel,
			TraceSchedule time) {
		if (thread instanceof TraceObjectThread tot) {
			TraceObject objThread = tot.getObject();
			if (frameLevel == null) {
				return objThread;
			}
			TraceStack stack =
				thread.getTrace().getStackManager().getStack(thread, time.getSnap(), false);
			if (stack == null) {
				return objThread;
			}
			TraceStackFrame frame = stack.getFrame(frameLevel, false);
			if (frame == null) {
				return objThread;
			}
			return ((TraceObjectStackFrame) frame).getObject();
		}
		return null;
	}

	/**
	 * Check if the object is a <em>canonical</em> ancestor
	 * 
	 * @param ancestor the proposed ancestor
	 * @param successor the proposed successor
	 * @param time the time to consider (only the snap matters)
	 * @return true if ancestor is in fact an ancestor of successor at the given time
	 */
	private static boolean isAncestor(TraceObject ancestor, TraceObject successor,
			TraceSchedule time) {
		return successor.getCanonicalParents(Range.singleton(time.getSnap()))
				.anyMatch(p -> p == ancestor);
	}

	public DebuggerCoordinates thread(TraceThread newThread) {
		if (thread == newThread) {
			return this;
		}
		if (newThread != null && trace != null && trace != newThread.getTrace()) {
			throw new IllegalArgumentException("Cannot change trace");
		}
		if (newThread == null) {
			newThread = resolveThread(recorder, getTime());
		}
		Trace newTrace = trace != null ? trace : newThread.getTrace();
		TraceSchedule newTime = time != null ? time : resolveTime(view);
		TraceProgramView newView = view != null ? view : resolveView(newTrace, newTime);
		// Yes, override frame with 0 on thread changes, unless target says otherwise
		Integer newFrame = resolveFrame(recorder, newThread, newTime);
		// Yes, forced frame change may also force object change
		TraceObject ancestor = resolveObject(newThread, newFrame, newTime);
		TraceObject newObject =
			object != null && isAncestor(ancestor, object, newTime) ? object : ancestor;
		return new DebuggerCoordinates(newTrace, recorder, newThread, newView, newTime, newFrame,
			newObject);
	}

	/**
	 * Get these same coordinates with time replaced by the given snap-only schedule
	 * 
	 * @param snap the new snap
	 * @return the new coordinates
	 */
	public DebuggerCoordinates snap(long snap) {
		return time(TraceSchedule.snap(snap));
	}

	public DebuggerCoordinates time(TraceSchedule newTime) {
		if (trace == null) {
			return NOWHERE;
		}
		long snap = newTime.getSnap();
		TraceThread newThread = thread != null && thread.getLifespan().contains(snap) ? thread
				: resolveThread(trace, recorder, newTime);
		// This will cause the frame to reset to 0 on every snap change. That's fair....
		Integer newFrame = resolveFrame(newThread, newTime);
		TraceObject ancestor = resolveObject(newThread, newFrame, newTime);
		TraceObject newObject =
			object != null && isAncestor(ancestor, object, newTime) ? object : ancestor;
		return new DebuggerCoordinates(trace, recorder, newThread, view, newTime, newFrame,
			newObject);
	}

	public DebuggerCoordinates frame(int newFrame) {
		if (trace == null) {
			return NOWHERE;
		}
		if (Objects.equals(frame, newFrame)) {
			return this;
		}
		TraceObject ancestor = resolveObject(thread, newFrame, getTime());
		TraceObject newObject =
			object != null && isAncestor(ancestor, object, getTime()) ? object : ancestor;
		return new DebuggerCoordinates(trace, recorder, thread, view, time, newFrame, newObject);
	}

	private DebuggerCoordinates replaceView(TraceProgramView newView) {
		return new DebuggerCoordinates(trace, recorder, thread, newView, time, frame, object);
	}

	private static TraceSchedule resolveTime(TraceProgramView view) {
		if (view == null) {
			return null;
		}
		long snap = view.getSnap();
		if (!DBTraceUtils.isScratch(snap)) {
			return TraceSchedule.snap(snap);
		}
		TraceSnapshot snapshot = view.getTrace().getTimeManager().getSnapshot(snap, false);
		if (snapshot == null) {
			return TraceSchedule.snap(snap);
		}
		TraceSchedule schedule = snapshot.getSchedule();
		if (schedule == null) {
			return TraceSchedule.snap(snap);
		}
		return schedule;
	}

	public DebuggerCoordinates view(TraceProgramView newView) {
		if (view == newView) {
			return this;
		}
		if (trace == null) {
			if (newView == null) {
				return NOWHERE;
			}
			return NOWHERE.trace(newView.getTrace())
					.time(resolveTime(newView))
					.replaceView(newView);
		}
		if (newView.getTrace() != trace) {
			throw new IllegalArgumentException("Cannot change trace");
		}
		return time(resolveTime(newView)).replaceView(newView);
	}

	private static TraceThread resolveThread(TraceObject object) {
		return object.queryCanonicalAncestorsInterface(TraceObjectThread.class)
				.findFirst()
				.orElse(null);
	}

	private static Integer resolveFrame(TraceObject object) {
		TraceObjectStackFrame frame =
			object.queryCanonicalAncestorsInterface(TraceObjectStackFrame.class)
					.findFirst()
					.orElse(null);
		return frame == null ? null : frame.getLevel();
	}

	public DebuggerCoordinates object(TraceObject newObject) {
		Trace newTrace;
		if (trace == null) {
			if (newObject == null) {
				return NOWHERE;
			}
			newTrace = newObject.getTrace();
		}
		else {
			if (newObject == null) {
				return new DebuggerCoordinates(trace, recorder, thread, view, time, frame,
					newObject);
			}
			if (newObject.getTrace() != trace) {
				throw new IllegalArgumentException("Cannot change trace");
			}
			newTrace = trace;
		}
		TraceThread newThread = resolveThread(newObject);
		Integer newFrame = resolveFrame(newObject);

		return new DebuggerCoordinates(newTrace, recorder, newThread, view, time, newFrame,
			newObject);
	}

	protected static TraceThread resolveThread(TraceRecorder recorder, TargetObject targetObject) {
		return recorder.getTraceThreadForSuccessor(targetObject);
	}

	protected static Integer resolveFrame(TraceRecorder recorder, TargetObject targetObject) {
		TraceStackFrame frame = recorder.getTraceStackFrameForSuccessor(targetObject);
		return frame == null ? null : frame.getLevel();
	}

	protected DebuggerCoordinates object(TraceObject traceObject, TargetObject targetObject) {
		if (traceObject != null) {
			return object(traceObject);
		}
		if (recorder == null) {
			throw new IllegalArgumentException("No recorder");
		}
		TraceThread newThread = resolveThread(recorder, targetObject);
		Integer newFrame = resolveFrame(recorder, targetObject);
		return new DebuggerCoordinates(trace, recorder, newThread, view, time, newFrame, null);
	}

	public DebuggerCoordinates object(TargetObject newObject) {
		return object(resolveObject(trace, newObject), newObject);
	}

	public Trace getTrace() {
		return trace;
	}

	public TraceRecorder getRecorder() {
		return recorder;
	}

	public TraceThread getThread() {
		return thread;
	}

	public TraceProgramView getView() {
		return view;
	}

	public long getSnap() {
		return getTime().getSnap();
	}

	public TraceSchedule getTime() {
		return time == null ? TraceSchedule.ZERO : time;
	}

	public int getFrame() {
		return frame == null ? 0 : frame;
	}

	public TraceObject getObject() {
		return object;
	}

	public synchronized long getViewSnap() {
		if (viewSnap != null) {
			return viewSnap;
		}
		TraceSchedule defaultedTime = getTime();
		if (defaultedTime.isSnapOnly()) {
			return viewSnap = defaultedTime.getSnap();
		}
		Collection<? extends TraceSnapshot> snapshots =
			trace.getTimeManager().getSnapshotsWithSchedule(defaultedTime);
		if (snapshots.isEmpty()) {
			Msg.warn(this,
				"Seems the emulation service did not create the requested snapshot, yet");
			// NB. Don't cache viewSnap. Maybe next time, we'll get it.
			return defaultedTime.getSnap();
		}
		return viewSnap = snapshots.iterator().next().getKey();
	}

	public synchronized TraceTimeViewport getViewport() {
		if (viewport != null) {
			return viewport;
		}
		if (trace == null) {
			return null;
		}
		viewport = new DefaultTraceTimeViewport(trace);
		viewport.setSnap(getViewSnap());
		return viewport;
	}

	public void writeDataState(PluginTool tool, SaveState saveState, String key) {
		if (this == NOWHERE) {
			return;
		}
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
		if (time != null) {
			coordState.putString(KEY_TIME, time.toString());
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
			String key) {
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
		String timeSpec = coordState.getString(KEY_TIME, null);
		TraceSchedule time;
		try {
			time = TraceSchedule.parse(timeSpec);
		}
		catch (Exception e) {
			Msg.error(DebuggerCoordinates.class,
				"Could not restore invalid time specification: " + timeSpec);
			time = null;
		}
		Integer frame = null;
		if (coordState.hasValue(KEY_FRAME)) {
			frame = coordState.getInt(KEY_FRAME, 0);
		}
		TraceObject object = null;
		if (trace != null && coordState.hasValue(KEY_OBJ_PATH)) {
			String pathString = coordState.getString(KEY_OBJ_PATH, "");
			try {
				TraceObjectKeyPath path = TraceObjectKeyPath.parse(pathString);
				object = trace.getObjectManager().getObjectByCanonicalPath(path);
			}
			catch (Exception e) {
				Msg.error(DebuggerCoordinates.class, "Could not restore object: " + pathString, e);
				object = trace.getObjectManager().getRootObject();
			}
		}

		DebuggerCoordinates coords = DebuggerCoordinates.NOWHERE.trace(trace)
				.thread(thread)
				.time(time)
				.frame(frame)
				.object(object);
		return coords;
	}

	public boolean isAlive() {
		return recorder != null;
	}

	public boolean isPresent() {
		TraceSchedule defaultedTime = getTime();
		return recorder.getSnap() == defaultedTime.getSnap() && defaultedTime.isSnapOnly();
	}

	public boolean isReadsPresent() {
		return recorder.getSnap() == getTime().getSnap();
	}

	public boolean isAliveAndPresent() {
		return isAlive() && isPresent();
	}

	public boolean isDeadOrPresent() {
		return !isAlive() || isPresent();
	}

	public boolean isAliveAndReadsPresent() {
		return isAlive() && isReadsPresent();
	}
}
