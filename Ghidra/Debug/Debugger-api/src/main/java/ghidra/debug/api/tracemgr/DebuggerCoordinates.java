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
package ghidra.debug.api.tracemgr;

import java.io.IOException;
import java.util.*;

import org.jdom.Element;

import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.dbg.target.TargetObject;
import ghidra.debug.api.target.Target;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.trace.database.DBTraceContentHandler;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.stack.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.Msg;
import ghidra.util.NotOwnerException;

public class DebuggerCoordinates {

	/**
	 * Coordinates that indicate no trace is active in the Debugger UI.
	 * 
	 * <p>
	 * Typically, that only happens when no trace is open. Telling the trace manager to activate
	 * {@code NOWHERE} will cause it to instead activate the most recently active trace, which may
	 * very well be the current trace, resulting in no change. Internally, the trace manager will
	 * activate {@code NOWHERE} whenever the current trace is closed, effectively activating the
	 * most recent trace other than the one just closed.
	 */
	public static final DebuggerCoordinates NOWHERE =
		new DebuggerCoordinates(null, null, null, null, null, null, null, null);

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
		if (!Objects.equals(a.platform, b.platform)) {
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
	private final TracePlatform platform;
	private final Target target;
	private final TraceThread thread;
	private final TraceProgramView view;
	private final TraceSchedule time;
	private final Integer frame;
	private final TraceObjectKeyPath path;

	private final int hash;

	private Long viewSnap;
	private TraceObject object;
	private TraceObject registerContainer;

	DebuggerCoordinates(Trace trace, TracePlatform platform, Target target, TraceThread thread,
			TraceProgramView view, TraceSchedule time, Integer frame, TraceObjectKeyPath path) {
		this.trace = trace;
		this.platform = platform;
		this.target = target;
		this.thread = thread;
		this.view = view;
		this.time = time;
		this.frame = frame;
		this.path = path;

		this.hash = Objects.hash(trace, target, thread, view, time, frame, path);
	}

	@Override
	public String toString() {
		return String.format(
			"Coords(trace=%s,target=%s,thread=%s,view=%s,time=%s,frame=%d,path=%s)",
			trace, target, thread, view, time, frame, path);
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
		if (!Objects.equals(this.target, that.target)) {
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
		if (!Objects.equals(this.path, that.path)) {
			return false;
		}

		return true;
	}

	@Override
	public int hashCode() {
		return hash;
	}

	private static TracePlatform resolvePlatform(Trace trace) {
		return trace.getPlatformManager().getHostPlatform();
	}

	private static TraceThread resolveThread(Trace trace, TraceSchedule time) {
		long snap = time.getSnap();
		return trace.getThreadManager()
				.getLiveThreads(snap)
				.stream()
				.sorted(Comparator.comparing(TraceThread::getKey))
				.findFirst()
				.orElse(null);
	}

	private static TraceThread resolveThread(Trace trace) {
		return resolveThread(trace, TraceSchedule.ZERO);
	}

	private static TraceObjectKeyPath resolvePath(Trace trace, TraceThread thread, Integer frame,
			TraceSchedule time) {
		TraceObjectKeyPath path = resolvePath(thread, frame, time);
		if (path != null) {
			return path;
		}
		return TraceObjectKeyPath.of();
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
			TracePlatform newPlatform = resolvePlatform(newTrace);
			TraceThread newThread = resolveThread(newTrace);
			TraceProgramView newView = resolveView(newTrace);
			TraceSchedule newTime = null; // Allow later resolution
			Integer newFrame = resolveFrame(newThread, newTime);
			TraceObjectKeyPath newPath = resolvePath(newTrace, newThread, newFrame, newTime);
			return new DebuggerCoordinates(newTrace, newPlatform, null, newThread, newView, newTime,
				newFrame, newPath);
		}
		throw new IllegalArgumentException("Cannot change trace");
	}

	private static TraceThread resolveThread(Target target, TraceSchedule time) {
		if (target.getSnap() != time.getSnap() || !target.isSupportsFocus()) {
			return resolveThread(target.getTrace(), time);
		}
		return resolveThread(target, target.getFocus());
	}

	private static TraceThread resolveThread(Trace trace, Target target, TraceSchedule time) {
		if (target == null) {
			return resolveThread(trace, time);
		}
		return resolveThread(target, time);
	}

	private static Integer resolveFrame(TraceThread thread, TraceSchedule time) {
		// Use null to allow later resolution. Getter will default to 0
		return null;
	}

	private static Integer resolveFrame(Target target, TraceThread thread, TraceSchedule time) {
		if (target == null || target.getSnap() != time.getSnap() ||
			!target.isSupportsFocus()) {
			return resolveFrame(thread, time);
		}
		return resolveFrame(target, target.getFocus());
	}

	private static TraceObjectKeyPath resolvePath(Target target, TraceThread thread,
			Integer frame, TraceSchedule time) {
		if (target.getSnap() != time.getSnap() || !target.isSupportsFocus()) {
			return resolvePath(target.getTrace(), thread, frame, time);
		}
		return target.getFocus();
	}

	public DebuggerCoordinates platform(TracePlatform newPlatform) {
		if (platform == newPlatform) {
			return this;
		}
		if (newPlatform == null) {
			if (trace == null) {
				return NOWHERE;
			}
			return new DebuggerCoordinates(trace, resolvePlatform(trace), target, thread, view,
				time, frame, path);
		}
		if (trace == null) {
			Trace newTrace = newPlatform.getTrace();
			TraceThread newThread = resolveThread(newTrace);
			TraceProgramView newView = resolveView(newTrace);
			TraceSchedule newTime = null; // Allow later resolution
			Integer newFrame = resolveFrame(newThread, newTime);
			TraceObjectKeyPath newPath = resolvePath(newTrace, newThread, newFrame, newTime);
			return new DebuggerCoordinates(newTrace, newPlatform, null, newThread, newView, newTime,
				newFrame, newPath);
		}
		if (trace != newPlatform.getTrace()) {
			throw new IllegalArgumentException("Cannot change trace");
		}
		return new DebuggerCoordinates(trace, newPlatform, target, thread, view, time, frame, path);
	}

	public DebuggerCoordinates target(Target newTarget) {
		if (target == newTarget) {
			return this;
		}
		if (newTarget == null) {
			return new DebuggerCoordinates(trace, platform, newTarget, thread, view, time, frame,
				path);
		}
		if (newTarget != null && trace != null && newTarget.getTrace() != trace) {
			throw new IllegalArgumentException("Cannot change trace");
		}
		Trace newTrace = trace != null ? trace : newTarget.getTrace();
		TracePlatform newPlatform = platform != null ? platform : resolvePlatform(newTrace);
		TraceSchedule newTime = time != null ? time : TraceSchedule.snap(newTarget.getSnap());
		TraceThread newThread = thread != null ? thread : resolveThread(newTarget, newTime);
		TraceProgramView newView = view != null ? view : resolveView(newTrace, newTime);
		Integer newFrame = frame != null ? frame : resolveFrame(newTarget, newThread, newTime);
		TraceObjectKeyPath threadOrFramePath = resolvePath(newTarget, newThread, newFrame, newTime);
		TraceObjectKeyPath newPath = choose(path, threadOrFramePath);
		return new DebuggerCoordinates(newTrace, newPlatform, newTarget, newThread, newView,
			newTime, newFrame, newPath);
	}

	public DebuggerCoordinates reFindThread() {
		if (trace == null || thread == null) {
			return this;
		}
		return thread(trace.getThreadManager().getThread(thread.getKey()));
	}

	private static TraceObjectKeyPath resolvePath(TraceThread thread, Integer frameLevel,
			TraceSchedule time) {
		if (thread instanceof TraceObjectThread tot) {
			TraceObject objThread = tot.getObject();
			if (frameLevel == null) {
				return objThread.getCanonicalPath();
			}
			TraceStack stack;
			try {
				stack = thread.getTrace().getStackManager().getStack(thread, time.getSnap(), false);
			}
			catch (IllegalStateException e) {
				// Schema does not specify a stack
				return objThread.getCanonicalPath();
			}
			if (stack == null) {
				return objThread.getCanonicalPath();
			}
			TraceStackFrame frame = stack.getFrame(frameLevel, false);
			if (frame == null) {
				return objThread.getCanonicalPath();
			}
			return ((TraceObjectStackFrame) frame).getObject().getCanonicalPath();
		}
		return null;
	}

	private static TraceObjectKeyPath choose(TraceObjectKeyPath curPath,
			TraceObjectKeyPath newPath) {
		if (curPath == null) {
			return newPath;
		}
		if (newPath == null) {
			return curPath;
		}
		if (newPath.isAncestor(curPath)) {
			return curPath;
		}
		return newPath;
	}

	public DebuggerCoordinates thread(TraceThread newThread) {
		if (thread == newThread) {
			return this;
		}
		if (newThread != null && trace != null && trace != newThread.getTrace()) {
			throw new IllegalArgumentException("Cannot change trace");
		}
		if (newThread == null) {
			newThread = resolveThread(trace, target, getTime());
		}
		Trace newTrace = trace != null ? trace : newThread.getTrace();
		TracePlatform newPlatform = platform != null ? platform : resolvePlatform(newTrace);
		TraceSchedule newTime = time != null ? time : resolveTime(view);
		TraceProgramView newView = view != null ? view : resolveView(newTrace, newTime);
		// Yes, override frame with 0 on thread changes, unless target says otherwise
		Integer newFrame = resolveFrame(target, newThread, newTime);
		// Yes, forced frame change may also force object change
		TraceObjectKeyPath threadOrFramePath = resolvePath(newThread, newFrame, newTime);
		TraceObjectKeyPath newPath = choose(path, threadOrFramePath);
		return new DebuggerCoordinates(newTrace, newPlatform, target, newThread, newView, newTime,
			newFrame, newPath);
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

	/**
	 * Get these same coordinates with time replace by the given snap-only schedule, and DO NOT
	 * resolve or adjust anything else
	 * 
	 * @param snap the new snap
	 * @return exactly these same coordinates with the snap/time changed
	 */
	public DebuggerCoordinates snapNoResolve(long snap) {
		if (time != null && time.isSnapOnly() && time.getSnap() == snap) {
			return this;
		}
		TraceSchedule newTime = TraceSchedule.snap(snap);
		return new DebuggerCoordinates(trace, platform, target, thread, view, newTime, frame, path);
	}

	public DebuggerCoordinates time(TraceSchedule newTime) {
		if (trace == null) {
			return NOWHERE;
		}
		long snap = newTime.getSnap();
		Lifespan threadLifespan = thread == null ? null : thread.getLifespan();
		TraceThread newThread = threadLifespan != null && threadLifespan.contains(snap) ? thread
				: resolveThread(trace, target, newTime);
		// This will cause the frame to reset to 0 on every snap change. That's fair....
		Integer newFrame = resolveFrame(newThread, newTime);
		TraceObjectKeyPath threadOrFramePath = resolvePath(newThread, newFrame, newTime);
		TraceObjectKeyPath newPath = choose(path, threadOrFramePath);
		return new DebuggerCoordinates(trace, platform, target, newThread, view, newTime,
			newFrame, newPath);
	}

	public DebuggerCoordinates frame(int newFrame) {
		if (trace == null) {
			return NOWHERE;
		}
		if (Objects.equals(frame, newFrame)) {
			return this;
		}
		TraceObjectKeyPath threadOrFramePath = resolvePath(thread, newFrame, getTime());
		TraceObjectKeyPath newPath = choose(path, threadOrFramePath);
		return new DebuggerCoordinates(trace, platform, target, thread, view, time, newFrame,
			newPath);
	}

	public DebuggerCoordinates frame(Integer newFrame) {
		if (newFrame == null) {
			return this;
		}
		return frame(newFrame.intValue());
	}

	private DebuggerCoordinates replaceView(TraceProgramView newView) {
		return new DebuggerCoordinates(trace, platform, target, thread, newView, time, frame,
			path);
	}

	private static TraceSchedule resolveTime(TraceProgramView view) {
		if (view == null) {
			return null;
		}
		long snap = view.getSnap();
		if (!Lifespan.isScratch(snap)) {
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

	private static TraceThread resolveThread(Trace trace, TraceObjectKeyPath path) {
		TraceObject object = trace.getObjectManager().getObjectByCanonicalPath(path);
		if (object == null) {
			return null;
		}
		return object.queryCanonicalAncestorsInterface(TraceObjectThread.class)
				.findFirst()
				.orElse(null);
	}

	private static Integer resolveFrame(Trace trace, TraceObjectKeyPath path) {
		TraceObject object = trace.getObjectManager().getObjectByCanonicalPath(path);
		if (object == null) {
			return null;
		}
		TraceObjectStackFrame frame =
			object.queryCanonicalAncestorsInterface(TraceObjectStackFrame.class)
					.findFirst()
					.orElse(null);
		return frame == null ? null : frame.getLevel();
	}

	public DebuggerCoordinates path(TraceObjectKeyPath newPath) {
		if (trace == null && newPath == null) {
			return NOWHERE;
		}
		else if (trace == null) {
			throw new IllegalArgumentException("No trace");
		}
		else if (newPath == null) {
			return new DebuggerCoordinates(trace, platform, target, thread, view, time, frame,
				newPath);
		}
		TraceThread newThread = target != null
				? resolveThread(target, newPath)
				: resolveThread(trace, newPath);
		Integer newFrame = target != null
				? resolveFrame(target, newPath)
				: resolveFrame(trace, newPath);

		return new DebuggerCoordinates(trace, platform, target, newThread, view, time,
			newFrame, newPath);
	}

	public DebuggerCoordinates pathNonCanonical(TraceObjectKeyPath newPath) {
		if (trace == null && newPath == null) {
			return NOWHERE;
		}
		else if (trace == null) {
			throw new IllegalArgumentException("No trace");
		}
		else if (newPath == null) {
			return new DebuggerCoordinates(trace, platform, target, thread, view, time, frame,
				newPath);
		}
		TraceObject object = trace.getObjectManager().getObjectByCanonicalPath(newPath);
		if (object != null) {
			return path(newPath);
		}
		object = trace.getObjectManager()
				.getObjectsByPath(Lifespan.at(getSnap()), newPath)
				.findAny()
				.orElse(null);
		if (object != null) {
			return path(object.getCanonicalPath());
		}
		throw new IllegalArgumentException("No such object at path " + newPath);
	}

	protected static TraceThread resolveThread(Target target, TraceObjectKeyPath objectPath) {
		return target.getThreadForSuccessor(objectPath);
	}

	protected static Integer resolveFrame(Target target, TraceObjectKeyPath objectPath) {
		TraceStackFrame frame = target.getStackFrameForSuccessor(objectPath);
		return frame == null ? null : frame.getLevel();
	}

	public DebuggerCoordinates object(TargetObject targetObject) {
		return path(TraceObjectKeyPath.of(targetObject.getPath()));
	}

	public DebuggerCoordinates object(TraceObject newObject) {
		if (newObject == null) {
			return path(null);
		}
		return trace(newObject.getTrace()).path(newObject.getCanonicalPath());
	}

	public Trace getTrace() {
		return trace;
	}

	public TracePlatform getPlatform() {
		return platform;
	}

	public Target getTarget() {
		return target;
	}

	public TraceThread getThread() {
		return thread;
	}

	public TraceProgramView getView() {
		if (trace == null) {
			return view; // probably null
		}
		return view == null ? trace.getProgramView() : view;
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

	public TraceObjectKeyPath getPath() {
		return path;
	}

	private TraceObject doGetObject() {
		if (trace == null) {
			return null;
		}
		return trace.getObjectManager().getObjectByCanonicalPath(path);
	}

	public synchronized TraceObject getObject() {
		if (object == null) {
			object = doGetObject();
		}
		return object;
	}

	public TraceObject getRegisterContainer() {
		if (registerContainer != null) {
			return registerContainer;
		}
		return registerContainer = getObject().queryRegisterContainer(getFrame());
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
				// FIXME! orphaned instance - transient in nature
				projData = new DefaultProjectData(projLoc, false, false);
			}
			catch (NotOwnerException e) {
				Msg.error(DebuggerCoordinates.class,
					"Not project owner: " + projLoc + "(" + pathname + ")");
				return null;
			}
			catch (IOException | LockException e) {
				Msg.error(DebuggerCoordinates.class, "Project error: " + e.getMessage());
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
			Msg.error(DebuggerCoordinates.class, message);
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
			time = TraceSchedule.ZERO;
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
		return target != null && target.isValid();
	}

	protected boolean isPresent() {
		TraceSchedule defaultedTime = getTime();
		return target.getSnap() == defaultedTime.getSnap() && defaultedTime.isSnapOnly();
	}

	protected boolean isReadsPresent() {
		return target.getSnap() == getTime().getSnap();
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
