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

import java.util.List;
import java.util.Map;

import SWIG.*;
import agent.lldb.manager.LldbEvent;
import agent.lldb.manager.LldbManager;
import ghidra.comm.util.BitmaskUniverse;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;

/**
 * A wrapper for SBDebugger
 */
public interface DebugClient extends DebugClientReentrant {

	/**
	 * Create a debug client.
	 *
	 * @return a new client
	 */
	public static DebugClient debugCreate() {
		return new DebugClientImpl();
	}

	public static enum ExecutionState {
		RUNNING, STOPPED;
	}

	public static enum DebugStatus {
		NO_CHANGE(false, null, 13), //
		GO(true, ExecutionState.RUNNING, 10), //
		GO_HANDLED(true, ExecutionState.RUNNING, 9), //
		GO_NOT_HANDLED(true, ExecutionState.RUNNING, 8), //
		STEP_OVER(true, ExecutionState.RUNNING, 7), //
		STEP_INTO(true, ExecutionState.RUNNING, 5), //
		BREAK(false, ExecutionState.STOPPED, 0), //
		NO_DEBUGGEE(true, null, 1), // shouldWait is true to handle process creation
		STEP_BRANCH(true, ExecutionState.RUNNING, 6), //
		IGNORE_EVENT(false, null, 11), //
		RESTART_REQUESTED(true, null, 12), //
		REVERSE_GO(true, null, 0xff), //
		REVERSE_STEP_BRANCH(true, null, 0xff), //
		REVERSE_STEP_OVER(true, null, 0xff), //
		REVERSE_STEP_INTO(true, null, 0xff), //
		OUT_OF_SYNC(false, null, 2), //
		WAIT_INPUT(false, null, 3), //
		TIMEOUT(false, null, 4), //
		;

		public static final long MASK = 0xaf;
		public static final long INSIDE_WAIT = 0x100000000L;
		public static final long WAIT_TIMEOUT = 0x200000000L;

		DebugStatus(boolean shouldWait, ExecutionState threadState, int precedence) {
			this.shouldWait = shouldWait;
			this.threadState = threadState;
			this.precedence = precedence;
		}

		public final boolean shouldWait;
		public final ExecutionState threadState;
		public final int precedence; // 0 is highest

		public static DebugStatus fromArgument(StateType state) {
			if (state == null) {
				return DebugStatus.NO_DEBUGGEE;
			}
			switch (state.swigValue()) {
				case 0:	// eStateInvalid
				case 1: // eStateUnloaded
				case 2: // eStateConnected
				case 3: // eStateAttaching
				case 4: // eStateLaunching
					return DebugStatus.GO;
				case 5: // eStateStopped
					return DebugStatus.BREAK;
				case 6: // eStateRunning
					return DebugStatus.GO;
				case 7: // eStateStepping
					return DebugStatus.STEP_INTO;
				case 8:  // eStateCrashed
				case 9:  // eStateDetached
				case 10: // eStateExited
				case 11: // eStateSuspended
					return DebugStatus.NO_DEBUGGEE;
				default:
					return DebugStatus.NO_CHANGE;
			}
		}

		/*
		public static boolean isInsideWait(SBEvent event) {
			return (argument & INSIDE_WAIT) != 0;
		}
		
		public static boolean isWaitTimeout(SBEvent event) {
			return (argument & WAIT_TIMEOUT) != 0;
		}
		*/
	}

	public static enum SessionStatus {
		ACTIVE, //
		END_SESSION_ACTIVE_TERMINATE,//
		END_SESSION_ACTIVE_DETACH, //
		END_SESSION_PASSIVE, //
		END, //
		REBOOT, //
		HIBERNATE, //
		FAILURE, //
		;
	}

	public static enum ChangeSessionState implements BitmaskUniverse {
		SESSION_ALL(0xffffffff), //
		SESSION_BREAKPOINT_CHANGED(SBTarget.eBroadcastBitBreakpointChanged), //
		SESSION_MODULE_LOADED(SBTarget.eBroadcastBitModulesLoaded), //
		SESSION_MODULE_UNLOADED(SBTarget.eBroadcastBitModulesUnloaded), //
		SESSION_WATCHPOINT_CHANGED(SBTarget.eBroadcastBitWatchpointChanged), //
		SESSION_SYMBOLS_LOADED(SBTarget.eBroadcastBitSymbolsLoaded), //
		;

		private ChangeSessionState(int mask) {
			this.mask = mask;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static enum ChangeProcessState implements BitmaskUniverse {
		PROCESS_ALL(0xffffffff), //
		PROCESS_STATE_CHANGED(SBProcess.eBroadcastBitStateChanged), //
		PROCESS_INTERRUPT(SBProcess.eBroadcastBitInterrupt), //
		PROCESS_STDOUT(SBProcess.eBroadcastBitSTDOUT), //
		PROCESS_STDERR(SBProcess.eBroadcastBitSTDERR), //
		PROCESS_PROFILE_DATA(SBProcess.eBroadcastBitProfileData), //
		PROCESS_STRUCTURED_DATA(SBProcess.eBroadcastBitStructuredData), //
		;

		private ChangeProcessState(int mask) {
			this.mask = mask;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static enum ChangeThreadState implements BitmaskUniverse {
		THREAD_ALL(0xffffffff), //
		THREAD_STACK_CHANGED(SBThread.eBroadcastBitStackChanged), //
		THREAD_SUSPENDED(SBThread.eBroadcastBitThreadSuspended), //
		THREAD_RESUMED(SBThread.eBroadcastBitThreadResumed), //
		THREAD_FRAME_CHANGED(SBThread.eBroadcastBitSelectedFrameChanged), //
		THREAD_SELECTED(SBThread.eBroadcastBitThreadSelected), //
		;

		private ChangeThreadState(int mask) {
			this.mask = mask;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static enum DebugAttachFlags implements BitmaskUniverse {
		DEFAULT(0), //
		NONINVASIVE(1 << 0), //
		EXISTING(1 << 1), //
		NONINVASIVE_NO_SUSPEND(1 << 2), //
		INVASIVE_NO_INITIAL_BREAK(1 << 3), //
		INVASIVE_RESUME_PROCESS(1 << 4), //
		NONINVASIVE_ALLOW_PARTIAL(1 << 5), //
		;

		DebugAttachFlags(int mask) {
			this.mask = mask;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static enum DebugCreateFlags implements BitmaskUniverse {
		LAUNCH_DEFAULT(0), //
		LAUNCH_EXEC(1 << 0), //
		LAUNCH_DEBUG(1 << 1), //
		LAUNCH_STOP_AT_ENTRY(1 << 2), //
		LAUNCH_DISABLE_ASLR(1 << 3), //
		LAUNCH_DISABLE_STDIO(1 << 4), //
		LAUNCH_IN_TTY(1 << 5), //
		LAUNCH_IN_SHELL(1 << 6), //
		LAUNCH_IN_SEP_GROUP(1 << 7), //
		LAUNCH_DONT_SET_EXIT_STATUS(1 << 8), //
		LAUNCH_DETACH_ON_ERROR(1 << 9), //
		LAUNCH_SHELL_EXPAND_ARGS(1 << 10), //
		LAUNCH_CLOSE_TTY_ON_EXIT(1 << 11), //
		LAUNCH_INHERIT_FROM_PARENT(1 << 12) //
		;

		DebugCreateFlags(int mask) {
			this.mask = mask;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public enum DebugEndSessionFlags {
		DEBUG_END_PASSIVE(0x00000000),
		DEBUG_END_ACTIVE_TERMINATE(0x00000001),
		DEBUG_END_ACTIVE_DETACH(0x00000002),
		DEBUG_END_REENTRANT(0x00000003),
		DEBUG_END_DISCONNECT(0x00000004);

		DebugEndSessionFlags(int value) {
			this.value = value;
		}

		private final int value;

		public long getValue() {
			return value;
		}
	}

	public enum DebugOutputFlags {
		DEBUG_OUTPUT_NORMAL(0x1), //
		DEBUG_OUTPUT_ERROR(0x2), //
		DEBUG_OUTPUT_WARNING(0x4), //
		DEBUG_OUTPUT_VERBOSE(0x8), //
		DEBUG_OUTPUT_PROMPT(0x10), //
		DEBUG_OUTPUT_PROMPT_REGISTERS(0x20), //
		DEBUG_OUTPUT_EXTENSION_WARNING(0x40), //
		DEBUG_OUTPUT_DEBUGGEE(0x80), //
		DEBUG_OUTPUT_DEBUGGEE_PROMPT(0x100), //
		DEBUG_OUTPUT_SYMBOLS(0x200);

		DebugOutputFlags(int value) {
			this.value = value;
		}

		private final int value;

		public long getValue() {
			return value;
		}
	}

	public static String getModelKey(Object modelObject) {
		return modelObject.getClass() + ":" + getId(modelObject);
	}

	public static String getId(Object modelObject) {
		if (modelObject instanceof SBTarget) {
			SBTarget session = (SBTarget) modelObject;
			return Integer.toHexString(session.GetProcess().GetProcessID().intValue());
		}
		if (modelObject instanceof SBProcess) {  // global
			SBProcess process = (SBProcess) modelObject;
			return Integer.toHexString(process.GetProcessID().intValue());
		}
		if (modelObject instanceof SBThread) {  // global
			SBThread thread = (SBThread) modelObject;
			return Integer.toHexString(thread.GetThreadID().intValue());
		}
		if (modelObject instanceof SBFrame) {
			SBFrame frame = (SBFrame) modelObject;
			return Long.toHexString(frame.GetFrameID());
		}
		if (modelObject instanceof SBValue) {
			SBValue val = (SBValue) modelObject;
			return val.GetName();
		}
		if (modelObject instanceof SBModule) {
			SBModule module = (SBModule) modelObject;
			return module.GetFileSpec().GetFilename();
		}
		if (modelObject instanceof SBSection) {
			SBSection section = (SBSection) modelObject;
			return section.GetName() + ":" + section.GetFileAddress();
		}
		if (modelObject instanceof SBMemoryRegionInfo) {
			SBMemoryRegionInfo region = (SBMemoryRegionInfo) modelObject;
			return Long.toHexString(region.GetRegionBase().longValue());
		}
		if (modelObject instanceof SBSymbol) {
			SBSymbol sym = (SBSymbol) modelObject;
			return sym.GetName();
		}
		if (modelObject instanceof SBBreakpoint) {  // global
			SBBreakpoint spec = (SBBreakpoint) modelObject;
			return "B" + Integer.toHexString(spec.GetID());
		}
		if (modelObject instanceof SBWatchpoint) {  // global
			SBWatchpoint spec = (SBWatchpoint) modelObject;
			return "W" + Integer.toHexString(spec.GetID());
		}
		if (modelObject instanceof SBBreakpointLocation) {
			SBBreakpointLocation loc = (SBBreakpointLocation) modelObject;
			return Long.toHexString(loc.GetLoadAddress().longValue());
		}
		if (modelObject instanceof SBFunction) {
			SBFunction fn = (SBFunction) modelObject;
			return fn.GetName();
		}
		throw new RuntimeException("Unknown object " + modelObject.getClass());
	}

	public static TargetExecutionState convertState(StateType state) {
		switch (state.swigValue()) {
			case 0:	// eStateInvalid
				return TargetExecutionState.RUNNING;
			case 1: // eStateUnloaded
				return TargetExecutionState.INACTIVE;
			case 2: // eStateConnected
			case 3: // eStateAttaching
			case 4: // eStateLaunching
				return TargetExecutionState.ALIVE;
			case 5: // eStateStopped
				return TargetExecutionState.STOPPED;
			case 6: // eStateRunning
			case 7: // eStateStepping
				return TargetExecutionState.RUNNING;
			case 8:  // eStateCrashed
			case 9:  // eStateDetached
			case 10: // eStateExited
			case 11: // eStateSuspended
				return TargetExecutionState.TERMINATED;
			default:
				return TargetExecutionState.STOPPED;
		}
	}

	@Override
	public SBListener getListener();

	/**
	 * The the ID for the local server
	 * 
	 * @return the ID
	 */
	DebugServerId getLocalServer();

	void setOutputCallbacks(DebugOutputCallbacks cb);

	SBProcess attachProcess(DebugServerId si, int keyType, String key, boolean wait, boolean async);

	SBProcess createProcess(DebugServerId si, String fileName);

	SBProcess createProcess(DebugServerId si, String fileName,
			List<String> args, List<String> envp, String workingDir);

	SBProcess createProcess(DebugServerId si, SBLaunchInfo info);

	SBProcess createProcess(DebugServerId si, String fileName, List<String> args, List<String> envp,
			List<String> pathsIO,
			String workingDir, long createFlags, boolean stopAtEntry);

	void terminateCurrentProcess();

	void destroyCurrentProcess();

	void detachCurrentProcess();

	SBTarget connectSession(String commandLine);

	Map<String, SBTarget> listSessions();

	void endSession(DebugEndSessionFlags flags);

	void openDumpFileWide(String fileName);

	SBEvent waitForEvent();

	DebugStatus getExecutionStatus();

	void processEvent(LldbEvent<?> lldbEvt);

	boolean getInterrupt();

	public void setManager(LldbManager manager);

	public void addBroadcaster(Object process);

	public void execute(String command);

}
