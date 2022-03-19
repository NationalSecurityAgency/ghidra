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
package agent.frida.frida;

import java.util.List;
import java.util.Map;

import agent.frida.manager.*;
import ghidra.comm.util.BitmaskUniverse;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;

/**
 * A wrapper for FridaDebugger
 */
public interface FridaClient extends FridaClientReentrant {

	/**
	 * Create a debug client.
	 *
	 * @return a new client
	 */
	public static FridaClient debugCreate() {
		return new FridaClientImpl();
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

		public static DebugStatus fromArgument(FridaState state) {
			if (state == null) {
				return DebugStatus.NO_DEBUGGEE;
			}
			switch (state) {
				case FRIDA_THREAD_UNINTERRUPTIBLE:	
					return DebugStatus.GO;
				case FRIDA_THREAD_STOPPED: 
					return DebugStatus.BREAK;
				case FRIDA_THREAD_RUNNING:
					return DebugStatus.GO;
				//case 7: // eStateStepping
				//	return DebugStatus.STEP_INTO;
				case FRIDA_THREAD_HALTED: 
				case FRIDA_THREAD_WAITING: 
					return DebugStatus.NO_DEBUGGEE;
				default:
					return DebugStatus.NO_CHANGE;
			}
		}

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
		;

		private ChangeSessionState(long eBroadcastBitBreakpointChanged) {
			this.mask = (int) eBroadcastBitBreakpointChanged;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static enum ChangeProcessState implements BitmaskUniverse {
		PROCESS_ALL(0xffffffff), //
		;

		private ChangeProcessState(long eBroadcastBitStateChanged) {
			this.mask = (int) eBroadcastBitStateChanged;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static enum ChangeThreadState implements BitmaskUniverse {
		THREAD_ALL(0xffffffff), //
		;

		private ChangeThreadState(long eBroadcastBitStackChanged) {
			this.mask = (int) eBroadcastBitStackChanged;
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
		if (modelObject == null) {
			return null;
		}
		return modelObject.getClass() + ":" + getId(modelObject);
	}

	public static String getId(Object modelObject) {
		if (modelObject instanceof FridaTarget) {
			FridaTarget target = (FridaTarget) modelObject;
			return Long.toHexString(target.getID());
		}
		if (modelObject instanceof FridaSession) {  // global
			FridaSession session = (FridaSession) modelObject;
			return Integer.toHexString(session.getProcess().getPID().intValue());
		}
		if (modelObject instanceof FridaProcess) {  // global
			FridaProcess process = (FridaProcess) modelObject;
			return Long.toHexString(process.getPID());
		}
		if (modelObject instanceof FridaThread) {  // global
			FridaThread thread = (FridaThread) modelObject;
			return Long.toHexString(thread.getTid());
		}
		if (modelObject instanceof FridaFrame) {
			FridaFrame frame = (FridaFrame) modelObject;
			return Long.toString(frame.getFrameID());
		}
		if (modelObject instanceof FridaValue) {
			FridaValue val = (FridaValue) modelObject;
			return val.getKey();
		}
		if (modelObject instanceof FridaModule) {
			FridaModule module = (FridaModule) modelObject;
			return module.getName();
		}
		if (modelObject instanceof FridaSection) {
			FridaSection section = (FridaSection) modelObject;
			return section.getRangeAddress();
		}
		if (modelObject instanceof FridaMemoryRegionInfo) {
			FridaMemoryRegionInfo region = (FridaMemoryRegionInfo) modelObject;
			return region.getRangeAddress();
		}
		if (modelObject instanceof FridaSymbol) {
			FridaSymbol sym = (FridaSymbol) modelObject;
			return sym.getName();
		}
		if (modelObject instanceof FridaImport) {
			FridaImport imp = (FridaImport) modelObject;
			return imp.getName();
		}
		if (modelObject instanceof FridaExport) {
			FridaExport exp = (FridaExport) modelObject;
			return exp.getName();
		}
		if (modelObject instanceof FridaFunction) {
			FridaFunction fn = (FridaFunction) modelObject;
			return fn.getFunctionName();
		}
		if (modelObject instanceof FridaFileSpec) {
			FridaFileSpec spec = (FridaFileSpec) modelObject;
			return spec.getPath();
		}
		throw new RuntimeException("Unknown object " + modelObject.getClass());
	}

	public static TargetExecutionState convertState(FridaState state) {
		if (state == null) {
			return TargetExecutionState.STOPPED;
		}
		switch (state) {
			case FRIDA_THREAD_RUNNING:	
				return TargetExecutionState.RUNNING;
			case FRIDA_THREAD_WAITING: 
				return TargetExecutionState.INACTIVE;
			case FRIDA_THREAD_UNINTERRUPTIBLE: 
				return TargetExecutionState.ALIVE;
			case FRIDA_THREAD_STOPPED: 
				return TargetExecutionState.STOPPED;
			case FRIDA_THREAD_HALTED:  
				return TargetExecutionState.TERMINATED;
			default:
				return TargetExecutionState.STOPPED;
		}
	}

	public static FridaState convertState(TargetExecutionState state) {
		switch (state) {
			case RUNNING:	
				return FridaState.FRIDA_THREAD_RUNNING;
			case INACTIVE: 
				return FridaState.FRIDA_THREAD_WAITING;
			case ALIVE: 
				return FridaState.FRIDA_THREAD_UNINTERRUPTIBLE;
			case STOPPED: 
				return FridaState.FRIDA_THREAD_STOPPED;
			case TERMINATED:  
				return FridaState.FRIDA_THREAD_HALTED;
			default:
				return FridaState.FRIDA_THREAD_STOPPED;
		}
	}

	/**
	 * The the ID for the local server
	 * 
	 * @return the ID
	 */
	FridaServerId getLocalServer();

	FridaSession attachProcess(FridaServerId si, int keyType, String key, boolean wait, boolean async);

	FridaSession createProcess(FridaServerId si, String fileName);

	FridaSession createProcess(FridaServerId si, String fileName,
			List<String> args, List<String> envp, String workingDir);

	FridaSession createProcess(FridaServerId si, String fileName, List<String> args, List<String> envp,
			List<String> pathsIO,
			String workingDir, long createFlags, boolean stopAtEntry);

	void terminateCurrentProcess(FridaTarget target);

	void destroyCurrentProcess(FridaTarget target);

	void detachCurrentProcess(FridaTarget target);

	FridaTarget connectSession(String commandLine);

	Map<String, FridaSession> listSessions();

	void endSession(FridaTarget target, DebugEndSessionFlags flags);

	DebugStatus getExecutionStatus();

	void processEvent(FridaEvent<?> fridaEvt);

	boolean getInterrupt();

	public void setManager(FridaManager manager);

}
