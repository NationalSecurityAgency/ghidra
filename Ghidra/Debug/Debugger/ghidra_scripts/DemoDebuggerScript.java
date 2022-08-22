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
//An example debugger script
//It launches the current program, places saved breakpoints, and runs it until termination.
//This script must be run from the Debugger tool, or another tool with the required plugins.
//This script has only been tested with /usr/bin/echo.
//@category Debugger
//@keybinding
//@menupath
//@toolbar

import java.util.Set;
import java.util.concurrent.TimeUnit;

import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer.LaunchResult;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.LogicalBreakpoint;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.program.model.address.Address;
import ghidra.trace.model.Trace;

public class DemoDebuggerScript extends GhidraScript implements FlatDebuggerAPI {

	@Override
	protected void run() throws Exception {
		/**
		 * Here we'll just launch the current program. Note that this is not guaranteed to succeed
		 * at all. Launching is subject to an opinion-based service. If no offers are made, this
		 * will fail. If the target system is missing required components, this will fail. If the
		 * target behaves in an unexpected way, this may fail. One example is targets without an
		 * initial break. If Ghidra does not recognize the target platform, this will fail. Etc.,
		 * etc., this may fail.
		 * 
		 * In the event of failure, nothing is cleaned up automatically, since in some cases, the
		 * user may be expected to intervene. In our case; however, there's no way to continue this
		 * script on a repaired target, so we'll close the connection on failure. An alternative
		 * design for this script would expect the user to have already launched a target, and it
		 * would just operate on the "current target."
		 */
		println("Launching " + currentProgram);
		LaunchResult result = launch(monitor);
		if (result.exception() != null) {
			printerr("Failed to launch " + currentProgram + ": " + result.exception());

			if (result.model() != null) {
				result.model().close();
			}

			if (result.recorder() != null) {
				closeTrace(result.recorder().getTrace());
			}
			return;
		}
		Trace trace = result.recorder().getTrace();
		println("Successfully launched in trace " + trace);

		/**
		 * Breakpoints are highly dependent on the module map. To work correctly: 1) The target
		 * debugger must provide the module map. 2) Ghidra must have recorded that module map into
		 * the trace. 3) Ghidra must recognize the module names and map them to programs open in the
		 * tool. These events all occur asynchronously, usually immediately after launch. Most
		 * launchers will wait for the target program module to be mapped to its Ghidra program
		 * database, but the breakpoint service may still be processing the new mapping.
		 */
		flushAsyncPipelines(trace);

		/**
		 * There is also breakpointsEnable(), but that operates on an address-by-address basis,
		 * which doesn't quite make sense in this case. We'll instead use getBreakpoints(Program)
		 * and enable them only in the new trace. The nested for is to deal with the fact that
		 * getBreakpoints(Program) returns a map from address to breakpoint set, i.e., a collection
		 * of collections.
		 */
		println("Enabling breakpoints");
		for (Set<LogicalBreakpoint> bs : getBreakpoints(currentProgram).values()) {
			for (LogicalBreakpoint lb : bs) {
				println("  " + lb);
				if (lb.getTraceAddress(trace) == null) {
					printerr("    Not mapped!");
				}
				else {
					waitOn(lb.enableForTrace(trace));
				}
			}
		}

		/**
		 * This runs the target, recording memory around the PC and SP at each break, until it
		 * terminates.
		 */
		while (isTargetAlive()) {
			waitForBreak(10, TimeUnit.SECONDS);
			/**
			 * The recorder is going to schedule some reads upon break, so let's allow them to
			 * settle.
			 */
			flushAsyncPipelines(trace);

			println("Reading PC");
			Address pc = getProgramCounter();
			println("Reading 1024 bytes at PC=" + pc);
			readMemory(pc, 1024, monitor);
			println("Reading SP");
			Address sp = getStackPointer();
			println("Reading 8096 bytes at SP=" + sp);
			readMemory(sp, 8096, monitor);
			/**
			 * Allow the commands we just issued to settle.
			 */
			flushAsyncPipelines(trace);

			println("Resuming");
			resume();
		}
		println("Terminated");
	}
}
