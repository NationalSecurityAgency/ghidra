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
package ghidra.app.plugin.core.debug.service.breakpoint;

import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.debug.api.target.Target;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;

public interface LogicalBreakpointInternal extends LogicalBreakpoint {
	/**
	 * Set the expected address for trace breakpoints in the given trace
	 * 
	 * @param trace the trace
	 * @param address the address of this logical breakpoint in the given trace
	 */
	void setTraceAddress(Trace trace, Address address);

	void setTarget(Trace trace, Target target);

	/**
	 * Remove the given trace from this set
	 * 
	 * <p>
	 * This happens when a trace's recorder stops or when a trace is closed.
	 * 
	 * @param trace the trace no longer participating
	 */
	void removeTrace(Trace trace);

	boolean canMerge(Program program, Bookmark bookmark);

	/**
	 * Check if this logical breakpoint can subsume the given candidate trace breakpoint
	 * 
	 * <p>
	 * Note that logical breakpoints only include trace breakpoints for traces being actively
	 * recorded. All statuses regarding trace breakpoints are derived from the target breakpoints,
	 * i.e., they show the present status, regardless of the view's current time. A separate
	 * breakpoint history provider handles displaying records from the past, including dead traces.
	 * 
	 * @param breakpoint the trace breakpoint to check
	 * @return true if it can be aggregated.
	 * @throws TrackedTooSoonException if the containing trace is still being added to the manager
	 */
	boolean canMerge(TraceBreakpoint breakpoint) throws TrackedTooSoonException;

	boolean trackBreakpoint(Bookmark bookmark);

	boolean trackBreakpoint(TraceBreakpoint breakpoint);

	boolean untrackBreakpoint(TraceBreakpoint breakpoint);

	boolean untrackBreakpoint(Program program, Bookmark bookmark);

	/**
	 * Collect actions to enable a logical breakpoint.
	 * 
	 * @param actions the destination action set (plan)
	 * @param trace a trace, if actions should be limited to the given trace
	 * @return a future which completes when the actions are populated
	 */
	void planEnable(BreakpointActionSet actions, Trace trace);

	/**
	 * Collect actions to disable a logical breakpoint.
	 * 
	 * @param actions the destination action set (plan)
	 * @param trace a trace, if actions should be limited to the given trace
	 * @return a future which completes when the actions are populated
	 */
	void planDisable(BreakpointActionSet actions, Trace trace);

	/**
	 * Collect actions to delete a logical breakpoint.
	 * 
	 * @param actions the destination action set (plan)
	 * @param trace a trace, if actions should be limited to the given trace
	 * @return a future which completes when the actions are populated
	 */
	void planDelete(BreakpointActionSet actions, Trace trace);
}
