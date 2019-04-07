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
package ghidra.app.plugin.core.functiongraph.mvc;

import javax.swing.JComponent;

import ghidra.graph.viewer.GraphViewerUtils;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.RunManager;
import ghidra.util.task.SwingUpdateManager;

public class FGModel {

	private final FGController controller;

	private SwingUpdateManager updateManager;

	private RunManager runManager;
	private volatile FunctionGraphRunnable pendingGraphRunnable;
	private volatile FunctionGraphRunnable currentGraphRunnable;

	public FGModel(FGController controller) {
		this.controller = controller;

		runManager = new RunManager(GraphViewerUtils.GRAPH_BUILDER_THREAD_POOL_NAME, null);
		updateManager = new SwingUpdateManager(500, () -> doPendingFunctionGraph());
	}

	JComponent getTaskMonitorComponent() {
		return runManager.getMonitorComponent();
	}

	void reset() {
		updateManager.stop();
		cleanupCurrentRunnableState();
		cancelAll();
	}

	void cleanup() {
		reset();
	}

	synchronized void graphFunction(Program program, ProgramLocation location) {
		if (currentRunnableContainsLocation(location)) {
			// already in the process of graphing; nothing to do
			return;
		}

		pendingGraphRunnable = new FunctionGraphRunnable(controller, program, location);
		updateManager.update();
		return;
	}

	private boolean currentRunnableContainsLocation(ProgramLocation location) {
		if (pendingGraphRunnable != null) {
			return false; // can't update when pending
		}

		if (currentGraphRunnable == null) {
			return false; // nothing to update
		}

		return currentGraphRunnable.containsLocation(location);
	}

	private synchronized void cleanupCurrentRunnableState() {
		currentGraphRunnable = null;
	}

	synchronized void cancelAll() {
		if (pendingGraphRunnable != null) {
			pendingGraphRunnable = null;
		}

		runManager.cancelAllRunnables();
	}

	private synchronized void doPendingFunctionGraph() {
		if (pendingGraphRunnable == null) {
			return; // somebody cleared the pending update
		}

		currentGraphRunnable = pendingGraphRunnable;
		pendingGraphRunnable = null;

		controller.setFunctionGraphData(new EmptyFunctionGraphData(
			"Graphing function at " + currentGraphRunnable.getLocation().getAddress()));
		runManager.runNow(currentGraphRunnable, "Graph Function", 500);
	}

	synchronized void setFunctionGraphData(FunctionGraphRunnable graphRunnable, FGData graphData) {

		if (currentGraphRunnable != graphRunnable) {
			return; // a new request has come in, ignore these outdated results
		}

		currentGraphRunnable = null;

		controller.setFunctionGraphData(graphData);
	}

	synchronized boolean isBusy() {
		return currentGraphRunnable != null || pendingGraphRunnable != null;
	}
}
