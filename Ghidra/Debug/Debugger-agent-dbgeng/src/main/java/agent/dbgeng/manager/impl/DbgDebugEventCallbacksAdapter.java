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
package agent.dbgeng.manager.impl;

import java.nio.file.Paths;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.dbgeng.DebugClient.ChangeEngineState;
import agent.dbgeng.dbgeng.DebugClient.DebugStatus;
import agent.dbgeng.dbgeng.util.DebugEventCallbacksAdapter;
import agent.dbgeng.manager.DbgState;
import agent.dbgeng.manager.evt.*;
import ghidra.comm.util.BitmaskSet;
import ghidra.util.Msg;

public class DbgDebugEventCallbacksAdapter extends DebugEventCallbacksAdapter {
	private DbgManagerImpl manager;

	public DbgDebugEventCallbacksAdapter(DbgManagerImpl manager) {
		super();
		this.manager = manager;
	}

	@Override
	public DebugStatus breakpoint(DebugBreakpoint bp) {
		Msg.info(this, "***Breakpoint: " + bp.getId());
		return manager.processEvent(new DbgBreakpointEvent(bp));
	}

	@Override
	public DebugStatus exception(DebugExceptionRecord64 exception, boolean firstChance) {
		Msg.info(this, "***Exception: " + exception + ", first=" + firstChance);
		return manager.processEvent(new DbgExceptionEvent(exception));
	}

	@Override
	public DebugStatus createThread(DebugThreadInfo threadInfo) {
		Msg.info(this, "***Thread created: " + Long.toHexString(threadInfo.handle));
		return manager.processEvent(new DbgThreadCreatedEvent(threadInfo));
	}

	@Override
	public DebugStatus exitThread(int exitCode) {
		Msg.info(this, "***Thread exited: " + exitCode);
		return manager.processEvent(new DbgThreadExitedEvent(exitCode));
	}

	@Override
	public DebugStatus createProcess(DebugProcessInfo processInfo) {
		Msg.info(this, "***Process created: " + Long.toHexString(processInfo.handle));
		Msg.info(this,
			" **Thread created: " + Long.toHexString(processInfo.initialThreadInfo.handle));
		return manager.processEvent(new DbgProcessCreatedEvent(processInfo));
	}

	@Override
	public DebugStatus exitProcess(int exitCode) {
		Msg.info(this, "***Process exited: " + exitCode);
		Msg.info(this, " **Thread exited");
		return manager.processEvent(new DbgProcessExitedEvent(exitCode));
	}

	@Override
	public DebugStatus loadModule(DebugModuleInfo moduleInfo) {
		Msg.info(this, "***Module Loaded: " + moduleInfo);
		return manager.processEvent(new DbgModuleLoadedEvent(moduleInfo));
	}

	@Override
	public DebugStatus unloadModule(String imageBaseName, long baseOffset) {
		Msg.info(this,
			"***Module Unloaded: " + imageBaseName + ", " + Long.toHexString(baseOffset));
		DebugModuleInfo info =
			new DebugModuleInfo(0L, baseOffset, 0, basename(imageBaseName), imageBaseName, 0, 0);
		return manager.processEvent(new DbgModuleUnloadedEvent(info));
	}

	private String basename(String path) {
		return Paths.get(path).getFileName().toString();
	}

	@Override
	public DebugStatus changeEngineState(BitmaskSet<ChangeEngineState> flags, long argument) {
		DbgStateChangedEvent event = new DbgStateChangedEvent(flags);
		event.setArgument(argument);
		if (flags.contains(ChangeEngineState.EXECUTION_STATUS)) {
			if (DebugStatus.isInsideWait(argument)) {
				return DebugStatus.NO_CHANGE;
			}
			Msg.info(this, "***ExecutionStatus: " + DebugStatus.fromArgument(argument));
			return manager.processEvent(event);
		}
		if (flags.contains(ChangeEngineState.BREAKPOINTS)) {
			Msg.info(this, "***BreakpointChanged: " + flags + ", " + argument + " on " +
				Thread.currentThread());
			return manager.processEvent(event);
		}
		if (flags.contains(ChangeEngineState.CURRENT_THREAD)) {
			Msg.info(this, "***CurrentThread: " + argument);
			if (argument < 0) {
				return manager.processEvent(event);
			}
		}
		if (flags.contains(ChangeEngineState.SYSTEMS)) {
			Msg.info(this, "***Systems: " + argument);
			event.setState(DbgState.RUNNING);
			return manager.processEvent(event);
		}
		return DebugStatus.NO_CHANGE;
	}

	//@Override
	//public DebugStatus changeDebuggeeState(BitmaskSet<ChangeDebuggeeState> flags, long argument) {
	//	System.err.println("CHANGE_DEBUGGEE_STATE: " + flags + ":" + argument);
	//	return DebugStatus.NO_CHANGE;
	//}

}
