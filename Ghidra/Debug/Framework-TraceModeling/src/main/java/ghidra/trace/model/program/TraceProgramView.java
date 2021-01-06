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
package ghidra.trace.model.program;

import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceTimeViewport;

/**
 * View of a trace at a particular time, as a program
 */
public interface TraceProgramView extends Program {
	/**
	 * Get the trace this view presents
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the current snap
	 * 
	 * @return the snap
	 */
	long getSnap();

	/**
	 * Get the viewport this view is using for forked queries
	 * 
	 * @return the viewport
	 */
	TraceTimeViewport getViewport();

	/**
	 * Get the latest snap
	 * 
	 * @return the maximum snap
	 */
	Long getMaxSnap();

	/**
	 * Get a view for registers of a given thread
	 * 
	 * @param thread the thread
	 * @param createIfAbsent true to create code and memory tables if absent (requires transaction)
	 * @return the view, of null if either code or memory table was absent and not created
	 */
	TraceProgramView getViewRegisters(TraceThread thread, boolean createIfAbsent);
}
