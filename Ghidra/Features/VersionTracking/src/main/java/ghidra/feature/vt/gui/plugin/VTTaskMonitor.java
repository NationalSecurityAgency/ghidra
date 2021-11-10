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
package ghidra.feature.vt.gui.plugin;

import ghidra.util.task.TaskMonitor;

/**
 * A class that allows the VT application to track the currently in-use task monitor.   The
 * {@link VTController} will set this value each time it runs a VT task via
 * {@link VTController#runVTTask(ghidra.feature.vt.gui.task.VtTask)}.
 *
 * <p>In general, all background tasks should take a task monitor.  However, some parts of the
 * VT API perform time-consuming work that does not require a task monitor.  This exposes a
 * design flaw of the API.  However, rather than add the task monitor to most API interfaces of
 * VT, we use this class to allow these poorly designed APIs to use the currently running task
 * monitor.
 *
 * <p>When using this monitor, it is expected that the client uses it only to check the state
 * of the cancelled flag.  Other monitor operations, such as updating progress and setting
 * messages, are discouraged.
 */
public class VTTaskMonitor {

	private static TaskMonitor monitor = TaskMonitor.DUMMY;

	static void setTaskMonitor(TaskMonitor m) {
		monitor = TaskMonitor.dummyIfNull(m);
	}

	/**
	 * Returns the current in-use task monitor or a dummy monitor if there is no task running
	 * @return the monitor
	 */
	public static TaskMonitor getTaskMonitor() {
		return monitor;
	}
}
