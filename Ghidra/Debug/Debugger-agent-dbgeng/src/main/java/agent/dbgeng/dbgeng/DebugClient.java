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
package agent.dbgeng.dbgeng;

import java.util.List;

import com.sun.jna.platform.win32.WinBase;

import agent.dbgeng.dbgeng.DebugRunningProcess.Description;
import agent.dbgeng.dbgeng.DebugRunningProcess.Description.ProcessDescriptionFlags;
import ghidra.comm.util.BitmaskSet;
import ghidra.comm.util.BitmaskUniverse;

/**
 * A wrapper for {@code IDebugClient} and its newer variants.
 */
public interface DebugClient extends DebugClientReentrant {
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

		public static DebugStatus fromArgument(long argument) {
			return values()[(int) (argument & MASK)];
		}

		public static boolean isInsideWait(long argument) {
			return (argument & INSIDE_WAIT) != 0;
		}

		public static boolean isWaitTimeout(long argument) {
			return (argument & WAIT_TIMEOUT) != 0;
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

	public static enum ChangeDebuggeeState implements BitmaskUniverse {
		ALL(0xffffffff), //
		REGISTERS(1 << 0), //
		DATA(1 << 1), //
		REFRESH(1 << 2), //
		;

		private ChangeDebuggeeState(int mask) {
			this.mask = mask;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static enum ChangeEngineState implements BitmaskUniverse {
		ALL(0xffffffff), //
		CURRENT_THREAD(1 << 0), //
		EFFECTIVE_PROCESSOR(1 << 1), //
		BREAKPOINTS(1 << 2), //
		CODE_LEVEL(1 << 3), //
		EXECUTION_STATUS(1 << 4), //
		ENGINE_OPTIONS(1 << 5), //
		LOG_FILE(1 << 6), //
		RADIX(1 << 7), //
		EVENT_FILTERS(1 << 8), //
		PROCESS_OPTIONS(1 << 9), //
		EXTENSIONS(1 << 10), //
		SYSTEMS(1 << 11), //
		ASSEMBLY_OPTIONS(1 << 12), //
		EXPRESSION_SYNTAX(1 << 13), //
		TEXT_REPLACEMENTS(1 << 14), //
		;

		private ChangeEngineState(int mask) {
			this.mask = mask;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	public static enum ChangeSymbolState implements BitmaskUniverse {
		ALL(0xffffffff), //
		LOADS(1 << 0), //
		UNLOADS(1 << 1), //
		SCOPE(1 << 2), //
		PATHS(1 << 3), //
		SYMBOL_OPTIONS(1 << 4), //
		TYPE_OPTIONS(1 << 5), //
		;

		private ChangeSymbolState(int mask) {
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
		DEBUG_PROCESS(WinBase.DEBUG_PROCESS), //
		DEBUG_ONLY_THIS_PROCESS(WinBase.DEBUG_ONLY_THIS_PROCESS), //
		CREATE_SUSPENDED(WinBase.CREATE_SUSPENDED), //
		DETACHED_PROCESS(WinBase.DETACHED_PROCESS), //

		CREATE_NEW_CONSOLE(WinBase.CREATE_NEW_CONSOLE), //
		//NORMAL_PRIORITY_CLASS(WinBase.NORMAL_PRIORITY_CLASS), //
		//IDLE_PRIORITY_CLASS(WinBase.IDLE_PRIORITY_CLASS), //
		//HIGH_PRIORITY_CLASS(WinBase.HIGH_PRIORITY_CLASS), //

		//REALTIME_PRIORITY_CLASS(WinBase.REALTIME_PRIORITY_CLASS), //
		CREATE_NEW_PROCESS_GROUP(WinBase.CREATE_NEW_PROCESS_GROUP), //
		CREATE_UNICODE_ENVIRONMENT(WinBase.CREATE_UNICODE_ENVIRONMENT), //
		CREATE_SEPARATE_WOW_VDM(WinBase.CREATE_SEPARATE_WOW_VDM), //

		CREATE_SHARED_WOW_VDM(WinBase.CREATE_SHARED_WOW_VDM), //
		CREATE_FORCEDOS(WinBase.CREATE_FORCEDOS), //
		//BELOW_NORMAL_PRIORITY_CLASS(WinBase.BELOW_NORMAL_PRIORITY_CLASS), //
		//ABOVE_NORMAL_PRIORITY_CLASS(WinBase.ABOVE_NORMAL_PRIORITY_CLASS), //

		INHERIT_PARENT_AFFINITY(WinBase.INHERIT_PARENT_AFFINITY), //
		//INHERIT_CALLER_PRIORITY(WinBase.INHERIT_CALLER_PRIORITY), //
		CREATE_PROTECTED_PROCESS(WinBase.CREATE_PROTECTED_PROCESS), //
		EXTENDED_STARTUPINFO_PRESENT(WinBase.EXTENDED_STARTUPINFO_PRESENT), //

		//PROCESS_MODE_BACKGROUND_BEGIN(WinBase.PROCESS_MODE_BACKGROUND_BEGIN), //
		//PROCESS_MODE_BACKGROUND_END(WinBase.PROCESS_MODE_BACKGROUND_END), //

		CREATE_BREAKAWAY_FROM_JOB(WinBase.CREATE_BREAKAWAY_FROM_JOB), //
		CREATE_PRESERVE_CODE_AUTHZ_LEVEL(WinBase.CREATE_PRESERVE_CODE_AUTHZ_LEVEL), //
		CREATE_DEFAULT_ERROR_MODE(WinBase.CREATE_DEFAULT_ERROR_MODE), //
		CREATE_NO_WINDOW(WinBase.CREATE_NO_WINDOW), //

		//PROFILE_USER(WinBase.PROFILE_USER), //
		//PROFILE_KERNEL(WinBase.PROFILE_KERNEL), //     
		//PROFILE_SERVER(WinBase.PROFILE_SERVER), //
		//CREATE_IGNORE_SYSTEM_DEFAULT(WinBase.CREATE_IGNORE_SYSTEM_DEFAULT), //
		DEBUG_CREATE_NO_DEBUG_HEAP(0x00000400), //
		DEBUG_CREATE_THROUGH_RTL(0x00010000), //
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

	/**
	 * Obtain the advanced interface to this client.
	 * 
	 * @return the advanced interface
	 */
	DebugAdvanced getAdvanced();

	/**
	 * Obtain the control interface to this client
	 * 
	 * @return the control interface
	 */
	@Override
	DebugControl getControl();

	/**
	 * Obtain the data spaces interface to this client
	 * 
	 * @return the data spaces interface
	 */
	DebugDataSpaces getDataSpaces();

	/**
	 * Obtain the registers interface to this client
	 * 
	 * @return the registers interface
	 */
	DebugRegisters getRegisters();

	/**
	 * Obtain the symbols interface to this client
	 * 
	 * @return the symbols interface
	 */
	DebugSymbols getSymbols();

	/**
	 * Obtain the system objects interface to this client
	 * 
	 * @return the system objects interface
	 */
	DebugSystemObjects getSystemObjects();

	/**
	 * The the ID for the local server
	 * 
	 * @return the ID
	 */
	DebugServerId getLocalServer();

	void attachKernel(long flags, String options);

	void startProcessServer(String options);

	DebugServerId connectProcessServer(String options);

	boolean dispatchCallbacks(int timeout);

	void flushCallbacks();

	default void dispatchCallbacks() {
		this.dispatchCallbacks(-1);
	}

	void exitDispatch(DebugClient client);

	default void exitDispatch() {
		exitDispatch(this);
	}

	void setInputCallbacks(DebugInputCallbacks cb);

	void setOutputCallbacks(DebugOutputCallbacks cb);

	void setEventCallbacks(DebugEventCallbacks cb);

	List<DebugRunningProcess> getRunningProcesses(DebugServerId server);

	Description getProcessDescription(DebugServerId si, int systemId,
			BitmaskSet<ProcessDescriptionFlags> flags);

	void attachProcess(DebugServerId si, long processId, BitmaskSet<DebugAttachFlags> attachFlags);

	void createProcess(DebugServerId si, String commandLine,
			BitmaskSet<DebugCreateFlags> createFlags);

	void createProcessAndAttach(DebugServerId si, String commandLine,
			BitmaskSet<DebugCreateFlags> createFlags, int processId,
			BitmaskSet<DebugAttachFlags> attachFlags);

	void startServer(String options);

	// Only in IDebugClient2

	void waitForProcessServerEnd(int timeout);

	default void waitForProcessServerEnd() {
		waitForProcessServerEnd(-1);
	}

	void terminateCurrentProcess();

	void detachCurrentProcess();

	void abandonCurrentProcess();

	void connectSession(int flags);

	void endSession(DebugEndSessionFlags flags);

	// Only in IDebugClient4+

	void openDumpFileWide(String fileName);

}
