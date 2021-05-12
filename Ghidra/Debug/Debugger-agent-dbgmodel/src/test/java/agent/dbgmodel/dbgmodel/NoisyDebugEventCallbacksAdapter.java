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
package agent.dbgmodel.dbgmodel;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugClient.*;
import agent.dbgeng.dbgeng.util.DebugEventCallbacksAdapter;
import ghidra.comm.util.BitmaskSet;
import ghidra.util.Msg;

public abstract class NoisyDebugEventCallbacksAdapter
		extends DebugEventCallbacksAdapter {

	final DebugStatus defaultStatus;

	public NoisyDebugEventCallbacksAdapter(DebugStatus defaultStatus) {
		this.defaultStatus = defaultStatus;
	}

	@Override
	public DebugStatus createProcess(DebugProcessInfo debugProcessInfo) {
		Msg.info(this, "createProcess: " + debugProcessInfo);
		return defaultStatus;
	}

	@Override
	public DebugStatus createThread(DebugThreadInfo debugThreadInfo) {
		Msg.info(this, "createThread: " + debugThreadInfo);
		return defaultStatus;
	}

	@Override
	public DebugStatus exitProcess(int exitCode) {
		Msg.info(this, "exitProcess: " + Integer.toHexString(exitCode));
		return defaultStatus;
	}

	@Override
	public DebugStatus breakpoint(DebugBreakpoint bp) {
		Msg.info(this, "breakpoint: " + bp);
		return defaultStatus;
	}

	@Override
	public DebugStatus changeDebuggeeState(BitmaskSet<ChangeDebuggeeState> flags,
			long argument) {
		Msg.info(this, "changeDebuggeeState: " + flags + ", " + Long.toHexString(argument));
		return defaultStatus;
	}

	@Override
	public DebugStatus changeEngineState(BitmaskSet<ChangeEngineState> flags, long argument) {
		if (flags.contains(ChangeEngineState.EXECUTION_STATUS)) {
			DebugStatus status = DebugStatus.values()[(int) (argument & 0x0_ffff_ffffL)];
			Msg.info(this, "changeEngineState: " + flags + ", " +
				Long.toHexString(argument) + " (" + status + ")");
		}
		else {
			Msg.info(this, "changeEngineState: " + flags + ", " + Long.toHexString(argument));
		}
		return defaultStatus;
	}

	@Override
	public DebugStatus changeSymbolState(BitmaskSet<ChangeSymbolState> flags, long argument) {
		Msg.info(this, "changeSymbolState: " + flags + ", " + Long.toHexString(argument));
		return defaultStatus;
	}

	@Override
	public DebugStatus exception(DebugExceptionRecord64 exception, boolean firstChance) {
		Msg.info(this, "exception: " + exception + ", " + firstChance);
		return defaultStatus;
	}

	@Override
	public DebugStatus exitThread(int exitCode) {
		Msg.info(this, "exitThread: " + Integer.toHexString(exitCode));
		return defaultStatus;
	}

	@Override
	public DebugStatus loadModule(DebugModuleInfo debugModuleInfo) {
		Msg.info(this, "loadModule: " + debugModuleInfo);
		return defaultStatus;
	}

	@Override
	public DebugStatus sessionStatus(SessionStatus status) {
		Msg.info(this, "sessionStatus: " + status);
		return defaultStatus;
	}

	@Override
	public DebugStatus systemError(int error, int level) {
		Msg.info(this, "systemError: " + error + ", " + level);
		return defaultStatus;
	}

	@Override
	public DebugStatus unloadModule(String imageBaseName, long baseOffset) {
		Msg.info(this, "unloadModule: " + imageBaseName + ", " + baseOffset);
		return defaultStatus;
	}
}
