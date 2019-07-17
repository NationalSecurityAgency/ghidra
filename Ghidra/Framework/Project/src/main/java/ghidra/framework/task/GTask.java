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
package ghidra.framework.task;

import ghidra.framework.model.UndoableDomainObject;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Interface for tasks to be run by {@link GTaskManager}.
 * 
 * @see GTaskGroup
 */
public interface GTask {

	/**
	 * Returns the name of this task.
	 * @return  the name of this task.
	 */
	public String getName();

	/**
	 * the run method where work can be performed on the given domain object.
	 * @param domainObject the object to affect.
	 * @param monitor the taskMonitor to be used to cancel and report progress.
	 * @throws CancelledException if the user cancelled the task.
	 */
	public void run(UndoableDomainObject domainObject, TaskMonitor monitor)
			throws CancelledException;

}
