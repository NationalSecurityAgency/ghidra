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
package ghidra.framework.task.gui.taskview;

import ghidra.framework.task.GScheduledTask;

public class TaskInfo extends AbstractTaskInfo {
	protected GScheduledTask task;

	TaskInfo(GScheduledTask task) {
		this(task, false);
	}

	public TaskInfo(GScheduledTask task, boolean useAnimation) {
		super(task.getGroup(), useAnimation);
		this.task = task;
	}

	@Override
	protected String getLabelText() {
		StringBuffer buf = new StringBuffer("Task: ");
		buf.append(task.getDescription());
		buf.append(" (");
		buf.append(task.getPriority());
		buf.append(")");
		return buf.toString();
	}

	@Override
	public String toString() {
		return "Task Element: " + task.getDescription() + "(" + task.getDescription() + ")";
	}

	@Override
	protected int getIndention() {
		return 20;
	}

	public GScheduledTask getScheduledTask() {
		return task;
	}

}
