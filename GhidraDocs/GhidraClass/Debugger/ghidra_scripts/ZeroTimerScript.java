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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.LogicalBreakpoint;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;

public class ZeroTimerScript extends GhidraScript implements FlatDebuggerAPI {
	@Override
	protected void run() throws Exception {
		// --------------------------------
		Trace trace = getCurrentTrace();
		if (trace == null) {
			throw new AssertionError("There is no active session");
		}

		if (!"termmines".equals(currentProgram.getName())) {
			throw new AssertionError("The current program must be termmines");
		}

		if (getExecutionState(trace).isRunning()) {
			monitor.setMessage("Interrupting target and waiting for STOPPED");
			interrupt();
			waitForBreak(3, TimeUnit.SECONDS);
		}
		flushAsyncPipelines(trace);

		if (!getControlService().getCurrentMode(trace).canEdit(getCurrentDebuggerCoordinates())) {
			throw new AssertionError("Current control mode is read-only");
		}

		// --------------------------------
		List<Symbol> timerSyms = getSymbols("timer", null);
		if (timerSyms.isEmpty()) {
			throw new AssertionError("Symbol 'timer' is required");
		}
		List<Function> winFuncs = getGlobalFunctions("print_win");
		if (winFuncs.isEmpty()) {
			throw new AssertionError("Function 'print_win' is required");
		}
		List<Symbol> resetSyms = getSymbols("reset_timer", winFuncs.get(0));
		if (resetSyms.isEmpty()) {
			throw new AssertionError("Symbol 'reset_timer' is required");
		}

		Address timerDyn = translateStaticToDynamic(timerSyms.get(0).getAddress());
		if (timerDyn == null) {
			throw new AssertionError("Symbol 'timer' is not mapped to target");
		}
		Address resetDyn = translateStaticToDynamic(resetSyms.get(0).getAddress());
		if (resetDyn == null) {
			throw new AssertionError("Symbol 'reset_timer' is not mapped to target");
		}

		// --------------------------------
		ProgramLocation breakLoc =
			new ProgramLocation(currentProgram, resetSyms.get(0).getAddress());
		Set<LogicalBreakpoint> breaks = breakpointsEnable(breakLoc);
		if (breaks == null || breaks.isEmpty()) {
			breakpointSetSoftwareExecute(breakLoc, "reset timer");
		}

		// --------------------------------
		while (true) {
			monitor.checkCanceled();

			TargetExecutionState execState = getExecutionState(trace);
			switch (execState) {
				case STOPPED:
					resume();
					break;
				case TERMINATED:
				case INACTIVE:
					throw new AssertionError("Target terminated");
				case ALIVE:
					println(
						"I don't know whether or not the target is running. Please make it RUNNING.");
					break;
				case RUNNING:
					/**
					 * Probably timed out waiting for break. That's fine. Give the player time to
					 * win.
					 */
					break;
				default:
					throw new AssertionError("Unrecognized state: " + execState);
			}
			try {
				monitor.setMessage("Waiting for player to win");
				waitForBreak(1, TimeUnit.SECONDS);
			}
			catch (TimeoutException e) {
				// Give the player time to win.
				continue;
			}
			flushAsyncPipelines(trace);
			Address pc = getProgramCounter();
			println("STOPPED at pc = " + pc);
			if (resetDyn.equals(pc)) {
				break;
			}
		}

		// --------------------------------
		int time = readRegister("ECX").getUnsignedValue().intValue();
		if (!writeMemory(timerDyn,
			ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(time).array())) {
			throw new AssertionError("Could not write over timer. Does control mode allow edits?");
		}

		resume();
	}
}
