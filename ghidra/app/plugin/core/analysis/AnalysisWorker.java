/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.analysis;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>AnalysisWorker</code> provides an analysis callback which will be 
 * invoked while analysis is suspended.
 */
public interface AnalysisWorker {

	/**
	 * Analysis worker callback which performs the desired changes to program
	 * while analysis is suspended.
	 * @param program target program
	 * @param workerContext worker context provided to AutoAnalysisManager when
	 * worker was scheduled.
	 * @param monitor worker monitor
	 * @return final return to blocked invocation of scheduleWorker or false
	 * if worker was cancelled
	 * @throws CancelledException operation was cancelled
	 * @throws Exception if worker exception occurs
	 * @see AutoAnalysisManager#scheduleWorker(AnalysisWorker, Object, boolean, TaskMonitor)
	 */
	public boolean analysisWorkerCallback(Program program, Object workerContext, TaskMonitor monitor)
			throws Exception, CancelledException;

	/**
	 * Returns worker name to be used for analysis task monitor.
	 * Name should be very short.
	 * @return worker name
	 */
	public String getWorkerName();

}
