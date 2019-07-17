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
package ghidra.app.plugin.core.diff;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.util.task.TaskMonitor;

/**
 * Command to apply diffs to current program.
 * 
 */
class NextDiffCommand extends BackgroundCommand {

	private ProgramDiffPlugin plugin;

	/**
	 * Constructor.
	 * @param plugin
	 * @param currentLocation
	 * @param diffControl
	 */
	NextDiffCommand(ProgramDiffPlugin plugin) {
		super("Next Difference", false, false, true);
		this.plugin = plugin;
	}

	/**
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		monitor.setMessage("NextDiffTask starting...");
		plugin.nextDiff();
		return true;
	}
}
