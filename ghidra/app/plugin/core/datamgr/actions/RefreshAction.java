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
package ghidra.app.plugin.core.datamgr.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.util.classfinder.ClassSearchTask;
import ghidra.util.task.*;

/**
 * Class for action to refresh the built-in data types from the class path.
 */
public class RefreshAction extends DockingAction implements TaskListener {

	private final DataTypeManagerPlugin plugin;

	public RefreshAction(DataTypeManagerPlugin plugin) {
		super("Refresh BuiltInTypes", plugin.getName());
		this.plugin = plugin;

		setMenuBarData(new MenuData(new String[] { "Refresh BuiltInTypes" }, null, "R2"));

		setDescription("Searches the class path to refresh the list of Ghidra BuiltIn data types.");
		setEnabled(true);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		setEnabled(false);

		Task task = new ClassSearchTask();
		task.addTaskListener(this);

		new TaskLauncher(task, plugin.getProvider().getComponent(), 0);
	}

	@Override
	public void taskCompleted(Task task) {
		setEnabled(true);
	}

	@Override
	public void taskCancelled(Task task) {
		setEnabled(true);
	}
}
