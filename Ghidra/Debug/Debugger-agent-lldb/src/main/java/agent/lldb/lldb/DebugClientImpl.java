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
package agent.lldb.lldb;

import java.math.BigInteger;
import java.util.*;

import SWIG.*;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.LldbManager;
import agent.lldb.manager.evt.*;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.Msg;

public class DebugClientImpl implements DebugClient {

	private LldbManager manager;
	private SBDebugger sbd;
	private SBTarget session;
	private SBEvent event;
	private DebugOutputCallbacks ocb;
	//private DebugEventCallbacks ecb;
	private SBCommandInterpreter cmd;

	public DebugClientImpl() {
	}

	@Override
	public DebugClient createClient() {
		try {
			if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.LINUX) {
				System.load("/usr/lib/liblldb.so");
			} else if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.MAC_OS_X) {
				System.load("/usr/lib/liblldb.dylib");				
			} else if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
				System.load("/usr/lib/liblldb.dll");				
			}
		}
		catch (UnsatisfiedLinkError ex) {
			Msg.error(this, "LLDB libraries not found for "+Platform.CURRENT_PLATFORM.getOperatingSystem());
		}
		SBError error = SBDebugger.InitializeWithErrorHandling();
		if (!error.Success()) {
			SBStream stream = new SBStream();
			error.GetDescription(stream);
			Msg.error(this, stream.GetData());
			return null;
		}
		event = new SBEvent();
		sbd = SBDebugger.Create();
		cmd = sbd.GetCommandInterpreter();
		return this;
	}

	public SBDebugger getDebugger() {
		return sbd;
	}

	@Override
	public SBListener getListener() {
		return sbd.GetListener();
	}

	@Override
	public DebugServerId getLocalServer() {
		return new DebugServerId(0);
	}

	@Override
	public SBProcess attachProcess(DebugServerId si, int keyType, String key, boolean wait,
			boolean async) {
		SBListener listener = new SBListener();
		SBError error = new SBError();
		session = createNullSession();
		SBProcess process;
		switch (keyType) {
			case 0:  // pid
				int radix = 10;
				if (key.startsWith("0x")) {
					key = key.substring(2);
					radix = 16;
				}
				BigInteger processId = new BigInteger(key, radix);
				process = session.AttachToProcessWithID(listener, processId, error);
				break;
			case 1:  // name
				process = session.AttachToProcessWithName(listener, key, wait, error);
				break;
			case 2:  // path
				SBAttachInfo info = new SBAttachInfo(key, wait, async);
				process = session.Attach(info, error);
				break;
			default:
				return null;
		}
		if (!error.Success()) {
			Msg.error(this, error.GetType() + " while attaching to " + key);
			SBStream stream = new SBStream();
			error.GetDescription(stream);
			Msg.error(this, stream.GetData());
			return null;
		}
		if (async) {
			manager.waitForEventEx();
		}
		else {
			manager.updateState(process);
		}
		return process;
	}

	@Override
	public SBProcess createProcess(DebugServerId si, String fileName) {
		return createProcess(si, fileName, new ArrayList<String>(), new ArrayList<String>(), "");
	}

	@Override
	public SBProcess createProcess(DebugServerId si, String fileName,
			List<String> args, List<String> envp, String workingDir) {
		SBError error = new SBError();
		session = connectSession(fileName);
		String[] argArr = args.toArray(new String[args.size()]);
		String[] envArr = envp.isEmpty() ? null : envp.toArray(new String[envp.size()]);
		SBProcess process = session.LaunchSimple(argArr, envArr, workingDir);
		if (!error.Success()) {
			Msg.error(this, error.GetType() + " for create process");
			SBStream stream = new SBStream();
			error.GetDescription(stream);
			Msg.error(this, stream.GetData());
			return null;
		}
		manager.updateState(process);
		return process;
	}

	@Override
	public SBProcess createProcess(DebugServerId si, SBLaunchInfo info) {
		SBError error = new SBError();
		String cmd = info.GetExecutableFile().GetDirectory();
		cmd += "/" + info.GetExecutableFile().GetFilename();
		for (int i = 0; i < info.GetNumArguments(); i++) {
			cmd += " " + info.GetArgumentAtIndex(i);
		}
		session = connectSession(cmd);
		SBProcess process = session.Launch(info, error);
		if (!error.Success()) {
			Msg.error(this, error.GetType() + " for create process");
			SBStream stream = new SBStream();
			error.GetDescription(stream);
			Msg.error(this, stream.GetData());
			return null;
		}
		return process;
	}

	@Override
	public SBProcess createProcess(DebugServerId si, String fileName,
			List<String> args, List<String> envp, List<String> pathsIO,
			String workingDir, long createFlags, boolean stopAtEntry) {
		session = connectSession(fileName);

		String[] argArr = args.toArray(new String[args.size()]);
		// null for envp means use the default environment
		String[] envArr = envp.isEmpty() ? null : envp.toArray(new String[envp.size()]);
		String pathSTDIN = pathsIO.get(0);
		String pathSTDOUT = pathsIO.get(1);
		String pathSTDERR = pathsIO.get(2);
		SBListener listener = new SBListener();
		SBError error = new SBError();
		SBProcess process = session.Launch(listener, argArr, envArr,
			pathSTDIN, pathSTDOUT, pathSTDERR, workingDir, createFlags, stopAtEntry, error);
		//SBProcess process = session.Launch(listener, null, null, "", "", "", "", 0, true, error);
		if (!error.Success()) {
			Msg.error(this, error.GetType() + " while launching " + fileName);
			SBStream stream = new SBStream();
			error.GetDescription(stream);
			Msg.error(this, stream.GetData());
			return null;
		}
		if (stopAtEntry) {
			manager.updateState(process);
		}
		else {
			manager.waitForEventEx();
		}
		return process;
	}

	@Override
	public void terminateCurrentProcess() {
		SBProcess process = session.GetProcess();
		SBError error = process.Kill();
		if (!error.Success()) {
			SBStream stream = new SBStream();
			error.GetDescription(stream);
			Msg.error(this, stream.GetData());
		}
	}

	@Override
	public void destroyCurrentProcess() {
		SBProcess process = session.GetProcess();
		SBError error = process.Destroy();
		if (!error.Success()) {
			SBStream stream = new SBStream();
			error.GetDescription(stream);
			Msg.error(this, stream.GetData());
		}
	}

	@Override
	public void detachCurrentProcess() {
		SBProcess process = session.GetProcess();
		SBError error = process.Detach();
		if (!error.Success()) {
			SBStream stream = new SBStream();
			error.GetDescription(stream);
			Msg.error(this, stream.GetData());
		}
	}

	public SBTarget createNullSession() {
		return sbd.GetDummyTarget();
	}

	@Override
	public SBTarget connectSession(String fileName) {
		return sbd.CreateTarget(fileName);
	}

	@Override
	public Map<String, SBTarget> listSessions() {
		Map<String, SBTarget> map = new HashMap<>();
		for (int i = 0; i < sbd.GetNumTargets(); i++) {
			SBTarget target = sbd.GetTargetAtIndex(i);
			map.put(DebugClient.getId(target), target);
		}
		return map;
	}

	@Override
	public void endSession(DebugEndSessionFlags flags) {
		sbd.DeleteTarget(session);
	}

	@Override
	public void openDumpFileWide(String fileName) {
		SBError error = new SBError();
		session.LoadCore(fileName, error);
		if (!error.Success()) {
			Msg.error(this, error.GetType() + " while loading " + fileName);
		}
	}

	@Override
	public SBEvent waitForEvent() {
		boolean eventFound = getListener().WaitForEvent(-1, event);
		if (eventFound) {
			return event;
		}
		return null;
	}

	public void translateAndFireEvent(SBEvent evt) {
		manager.setCurrentEvent(evt);
		long type = evt.GetType();
		if (SBTarget.EventIsTargetEvent(evt)) {
			if ((type & SBTarget.eBroadcastBitBreakpointChanged) != 0) {
				Msg.info(this, "*** Breakpoint Changed: " + evt.GetType());
				SBBreakpoint bpt = SBBreakpoint.GetBreakpointFromEvent(evt);
				processEvent(new LldbBreakpointModifiedEvent(new DebugBreakpointInfo(evt, bpt)));
			}
			if ((type & SBTarget.eBroadcastBitModulesLoaded) != 0) {
				Msg.info(this, "*** Module Loaded: " + evt.GetType());
				processEvent(new LldbModuleLoadedEvent(new DebugModuleInfo(evt)));
			}
			if ((type & SBTarget.eBroadcastBitModulesUnloaded) != 0) {
				Msg.info(this, "*** Module Unloaded: " + evt.GetType());
				processEvent(new LldbModuleUnloadedEvent(new DebugModuleInfo(evt)));
			}
			if ((type & SBTarget.eBroadcastBitWatchpointChanged) != 0) {
				Msg.info(this, "*** Watchpoint Changed: " + evt.GetType());
				SBWatchpoint wpt = SBWatchpoint.GetWatchpointFromEvent(evt);
				processEvent(new LldbBreakpointModifiedEvent(new DebugBreakpointInfo(evt, wpt)));
			}
			if ((type & SBTarget.eBroadcastBitSymbolsLoaded) != 0) {
				Msg.info(this, "*** Symbols Loaded: " + evt.GetType());
				processEvent(new LldbSymbolsLoadedEvent(new DebugEventInfo(evt)));
			}
		}

		if (SBProcess.EventIsProcessEvent(evt)) {
			DebugProcessInfo info = new DebugProcessInfo(evt);
			if ((type & SBProcess.eBroadcastBitStateChanged) != 0) {
				Msg.info(this, "*** State Changed: " + evt.GetType());  // Seen & handled
				processEvent(new LldbStateChangedEvent(info));
			}
			if ((type & SBProcess.eBroadcastBitInterrupt) != 0) {
				Msg.info(this, "*** Interrupt: " + evt.GetType());
				processEvent(new LldbInterruptEvent(info));
			}
			if ((type & SBProcess.eBroadcastBitSTDOUT) != 0) {
				Msg.info(this, "*** Console STDOUT: " + evt.GetType());
				processEvent(new LldbConsoleOutputEvent(info));
			}
			if ((type & SBProcess.eBroadcastBitSTDERR) != 0) {
				Msg.info(this, "*** Console STDERR: " + evt.GetType());
				processEvent(new LldbConsoleOutputEvent(info));
			}
			if ((type & SBProcess.eBroadcastBitProfileData) != 0) {
				Msg.info(this, "*** Profile Data Added: " + evt.GetType());
				processEvent(new LldbProfileDataEvent(info));
			}
			if ((type & SBProcess.eBroadcastBitStructuredData) != 0) {
				Msg.info(this, "*** Structured Data Added: " + evt.GetType());
				processEvent(new LldbStructuredDataEvent(info));
			}
		}

		if (SBThread.EventIsThreadEvent(evt)) {
			DebugThreadInfo info = new DebugThreadInfo(evt);
			if ((type & SBThread.eBroadcastBitStackChanged) != 0) {
				Msg.info(this, "*** Stack Changed: " + evt.GetType());
				processEvent(new LldbThreadStackChangedEvent(info));
			}
			if ((type & SBThread.eBroadcastBitThreadSuspended) != 0) {
				Msg.info(this, "*** Thread Suspended: " + evt.GetType());
				processEvent(new LldbThreadSuspendedEvent(info));
			}
			if ((type & SBThread.eBroadcastBitThreadResumed) != 0) {
				Msg.info(this, "*** Thread Resumed: " + evt.GetType());
				processEvent(new LldbThreadResumedEvent(info));
			}
			if ((type & SBThread.eBroadcastBitSelectedFrameChanged) != 0) {
				Msg.info(this, "*** Frame Selected: " + evt.GetType());
				processEvent(new LldbSelectedFrameChangedEvent(info));
			}
			if ((type & SBThread.eBroadcastBitThreadSelected) != 0) {
				Msg.info(this, "*** Thread Selected: " + evt.GetType());
				processEvent(new LldbThreadSelectedEvent(info));
			}
		}
		if (SBBreakpoint.EventIsBreakpointEvent(evt)) {
			BreakpointEventType btype = SBBreakpoint.GetBreakpointEventTypeFromEvent(evt);
			SBBreakpoint bpt = SBBreakpoint.GetBreakpointFromEvent(evt);
			DebugBreakpointInfo info = new DebugBreakpointInfo(evt, bpt);
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeAdded)) {
				Msg.info(this, "*** Breakpoint Added: " + bpt.GetID());  // Seen & handled
				processEvent(new LldbBreakpointCreatedEvent(info));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeAutoContinueChanged)) {
				Msg.info(this, "*** Breakpoint Auto Continue: " + bpt.GetID());
				processEvent(new LldbBreakpointAutoContinueChangedEvent(info));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeCommandChanged)) {
				Msg.info(this, "*** Breakpoint Command Changed: " + bpt.GetID());
				processEvent(new LldbBreakpointCommandChangedEvent(info));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeConditionChanged)) {
				Msg.info(this, "*** Breakpoint Condition Changed: " + bpt.GetID());
				processEvent(new LldbBreakpointConditionChangedEvent(info));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeDisabled)) {
				Msg.info(this, "*** Breakpoint Disabled: " + bpt.GetID());
				processEvent(new LldbBreakpointDisabledEvent(info));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeEnabled)) {
				Msg.info(this, "*** Breakpoint Enabled: " + bpt.GetID());
				processEvent(new LldbBreakpointEnabledEvent(info));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeIgnoreChanged)) {
				Msg.info(this, "*** Breakpoint Ignore Changed: " + bpt.GetID());
				processEvent(new LldbBreakpointIgnoreChangedEvent(info));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeInvalidType)) {
				Msg.info(this, "*** Breakpoint Invalid Type: " + bpt.GetID());
				processEvent(new LldbBreakpointInvalidatedEvent(info));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeLocationsAdded)) {
				Msg.info(this, "*** Breakpoint Locations Added: " + bpt.GetID());
				processEvent(new LldbBreakpointLocationsAddedEvent(info));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeLocationsRemoved)) {
				Msg.info(this, "*** Breakpoint Locations Removed: " + bpt.GetID());
				processEvent(new LldbBreakpointLocationsRemovedEvent(info));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeLocationsResolved)) {
				Msg.info(this, "*** Breakpoint Locations Resolved: " + bpt.GetID());  // Seen & handled?
				processEvent(new LldbBreakpointLocationsResolvedEvent(info));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeRemoved)) {
				Msg.info(this, "*** Breakpoint Removed: " + bpt.GetID());
				processEvent(new LldbBreakpointDeletedEvent(info));
			}
			if (btype.equals(BreakpointEventType.eBreakpointEventTypeThreadChanged)) {
				Msg.info(this, "*** Breakpoint Thread Changed: " + bpt.GetID());
				processEvent(new LldbBreakpointThreadChangedEvent(info));
			}
		}
		if (SBWatchpoint.EventIsWatchpointEvent(evt)) {
			WatchpointEventType wtype = SBWatchpoint.GetWatchpointEventTypeFromEvent(evt);
			SBWatchpoint wpt = SBWatchpoint.GetWatchpointFromEvent(evt);
			DebugBreakpointInfo info = new DebugBreakpointInfo(evt, wpt);
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeAdded)) {
				Msg.info(this, "*** Watchpoint Added: " + wpt.GetID());
				processEvent(new LldbBreakpointCreatedEvent(info));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeCommandChanged)) {
				Msg.info(this, "*** Watchpoint Command Changed: " + wpt.GetID());
				processEvent(new LldbBreakpointCommandChangedEvent(info));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeConditionChanged)) {
				Msg.info(this, "*** Watchpoint Condition Changed: " + wpt.GetID());
				processEvent(new LldbBreakpointConditionChangedEvent(info));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeDisabled)) {
				Msg.info(this, "*** Watchpoint Disabled: " + wpt.GetID());
				processEvent(new LldbBreakpointDisabledEvent(info));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeEnabled)) {
				Msg.info(this, "*** Watchpoint Enabled: " + wpt.GetID());
				processEvent(new LldbBreakpointEnabledEvent(info));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeIgnoreChanged)) {
				Msg.info(this, "*** Watchpoint Ignore Changed: " + wpt.GetID());
				processEvent(new LldbBreakpointIgnoreChangedEvent(info));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeInvalidType)) {
				Msg.info(this, "*** Watchpoint Invalid Type: " + wpt.GetID());
				processEvent(new LldbBreakpointInvalidatedEvent(info));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeRemoved)) {
				Msg.info(this, "*** Watchpoint Removed: " + wpt.GetID());
				processEvent(new LldbBreakpointDeletedEvent(info));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeThreadChanged)) {
				Msg.info(this, "*** Watchpoint Thread Changed: " + wpt.GetID());
				processEvent(new LldbBreakpointThreadChangedEvent(info));
			}
			if (wtype.equals(WatchpointEventType.eWatchpointEventTypeTypeChanged)) {
				Msg.info(this, "*** Watchpoint Type Changed: " + wpt.GetID());
				processEvent(new LldbBreakpointTypeChangedEvent(info));
			}
		}
	}

	@Override
	public void processEvent(LldbEvent<?> lldbEvt) {
		manager.processEvent(lldbEvt);
	}

	@Override
	public DebugStatus getExecutionStatus() {
		StateType state = manager.getState();
		return DebugStatus.fromArgument(state);
	}

	@Override
	public void setOutputCallbacks(DebugOutputCallbacks cb) {
		this.ocb = cb;
	}

	@Override
	public boolean getInterrupt() {
		return false;
	}

	@Override
	public void setManager(LldbManager manager) {
		this.manager = manager;
	}

	@Override
	public void addBroadcaster(Object object) {
		if (object instanceof SBCommandInterpreter) {
			SBCommandInterpreter interpreter = (SBCommandInterpreter) object;
			interpreter.GetBroadcaster()
					.AddListener(getListener(), ChangeSessionState.SESSION_ALL.getMask());
		}
		if (object instanceof SBTarget) {
			SBTarget session = (SBTarget) object;
			session.GetBroadcaster()
					.AddListener(getListener(), ChangeSessionState.SESSION_ALL.getMask());
		}
		if (object instanceof SBProcess) {
			SBProcess process = (SBProcess) object;
			process.GetBroadcaster()
					.AddListener(getListener(), ChangeProcessState.PROCESS_ALL.getMask());
		}
	}

	@Override
	public void execute(String command) {
		SBCommandReturnObject res = new SBCommandReturnObject();
		cmd.HandleCommand(command, res);
		if (res.GetErrorSize() > 0) {
			ocb.output(DebugOutputFlags.DEBUG_OUTPUT_ERROR.ordinal(), res.GetError());
		}
		if (res.GetOutputSize() > 0) {
			ocb.output(DebugOutputFlags.DEBUG_OUTPUT_NORMAL.ordinal(), res.GetOutput());
		}
	}

}
