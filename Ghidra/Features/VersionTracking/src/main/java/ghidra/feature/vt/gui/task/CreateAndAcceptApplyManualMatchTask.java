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
package ghidra.feature.vt.gui.task;

import java.util.ArrayList;

import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

public class CreateAndAcceptApplyManualMatchTask extends CreateManualMatchTask {

	private VTController controller;
	private boolean applyMarkup;

	/**
	 * A task that creates the indicated function match and then either accepts it or applies it.
	 * @param controller the controller for a version tracking session
	 * @param sourceFunction the source function in the function match
	 * @param destinationFunction the destination function in the function match
	 * @param applyMarkup true means apply the match. false means only accept the match.
	 */
	public CreateAndAcceptApplyManualMatchTask(VTController controller, Function sourceFunction,
			Function destinationFunction, boolean applyMarkup) {
		super("Create And Accept/Apply Manual Match", controller.getSession(), sourceFunction,
			destinationFunction);
		this.controller = controller;
		this.applyMarkup = applyMarkup;
	}

	@Override
	protected boolean runFollowOnTasks(TaskMonitor monitor) throws Exception {

		if (newlyCreatedMatch == null) {
			return false;
		}
		ArrayList<VTMatch> list = new ArrayList<>();
		list.add(newlyCreatedMatch);

		if (applyMarkup) {
			ApplyMatchTask applyMatchTask = new ApplyMatchTask(controller, list);
			boolean result = applyMatchTask.doWork(monitor);
			addErrors(applyMatchTask);
			return result;
		}
		AcceptMatchTask acceptMatchTask = new AcceptMatchTask(controller, list);
		boolean result = acceptMatchTask.doWork(monitor);
		addErrors(acceptMatchTask);
		return result;
	}
}
