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

import java.lang.annotation.*;

import agent.dbgeng.dbgeng.DebugClient.*;
import ghidra.comm.util.BitmaskSet;
import ghidra.comm.util.BitmaskUniverse;

/**
 * The interface for receiving event callbacks via {@code IDebugEventCallbacks} or a newer variant.
 * 
 * Note: The wrapper implementation will select the appropriate native interface version.
 * 
 * Note: Even though {@link #changeDebuggeeState(BitmaskSet, long)},
 * {@link #changeEngineState(BitmaskSet, long)} and {@link #changeSymbolState(BitmaskSet, long)}
 * purport to return a {@link DebugStatus}, the returned value is ignored by {@code dbgeng.dll}.
 */
public interface DebugEventCallbacks {
	public static enum DebugEvent implements BitmaskUniverse {
		BREAKPOINT(1 << 0), //
		EXCEPTION(1 << 1), //
		CREATE_THREAD(1 << 2), //
		EXIT_THREAD(1 << 3), //
		CREATE_PROCESS(1 << 4), //
		EXIT_PROCESS(1 << 5), //
		LOAD_MODULE(1 << 6), //
		UNLOAD_MODULE(1 << 7), //
		SYSTEM_ERROR(1 << 8), //
		SESSION_STATUS(1 << 9), //
		CHANGE_DEBUGEE_STATE(1 << 10), //
		CHANGE_ENGINE_STATE(1 << 11), //
		CHANGE_SYMBOL_STATE(1 << 12), //
		;

		private DebugEvent(int mask) {
			this.mask = mask;
		}

		private final int mask;

		@Override
		public long getMask() {
			return mask;
		}
	}

	/**
	 * An annotation for marking each callback with its interest flag.
	 */
	@Target(ElementType.METHOD)
	@Retention(RetentionPolicy.RUNTIME)
	static @interface ForInterest {
		/**
		 * The flag corresponding to the annotated callback method
		 * 
		 * @return the flag
		 */
		DebugEvent value();
	}

	BitmaskSet<DebugEvent> getInterestMask();

	@ForInterest(DebugEvent.BREAKPOINT)
	DebugStatus breakpoint(DebugBreakpoint bp);

	@ForInterest(DebugEvent.EXCEPTION)
	DebugStatus exception(DebugExceptionRecord64 exception, boolean firstChance);

	@ForInterest(DebugEvent.CREATE_THREAD)
	DebugStatus createThread(DebugThreadInfo debugThreadInfo);

	@ForInterest(DebugEvent.EXIT_THREAD)
	DebugStatus exitThread(int exitCode);

	@ForInterest(DebugEvent.CREATE_PROCESS)
	DebugStatus createProcess(DebugProcessInfo debugProcessInfo);

	@ForInterest(DebugEvent.EXIT_PROCESS)
	DebugStatus exitProcess(int exitCode);

	@ForInterest(DebugEvent.LOAD_MODULE)
	DebugStatus loadModule(DebugModuleInfo debugModuleInfo);

	@ForInterest(DebugEvent.UNLOAD_MODULE)
	DebugStatus unloadModule(String imageBaseName, long baseOffset);

	@ForInterest(DebugEvent.SYSTEM_ERROR)
	DebugStatus systemError(int error, int level);

	@ForInterest(DebugEvent.SESSION_STATUS)
	DebugStatus sessionStatus(SessionStatus status);

	@ForInterest(DebugEvent.CHANGE_DEBUGEE_STATE)
	DebugStatus changeDebuggeeState(BitmaskSet<ChangeDebuggeeState> flags, long argument);

	@ForInterest(DebugEvent.CHANGE_ENGINE_STATE)
	DebugStatus changeEngineState(BitmaskSet<ChangeEngineState> flags, long argument);

	@ForInterest(DebugEvent.CHANGE_SYMBOL_STATE)
	DebugStatus changeSymbolState(BitmaskSet<ChangeSymbolState> flags, long argument);
}
