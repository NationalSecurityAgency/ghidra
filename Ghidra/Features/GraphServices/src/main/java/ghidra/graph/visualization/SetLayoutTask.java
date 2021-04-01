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
package ghidra.graph.visualization;

import java.util.concurrent.CountDownLatch;

import org.jgrapht.Graph;
import org.jungrapht.visualization.VisualizationModel;
import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.layout.event.LayoutStateChange.*;
import org.jungrapht.visualization.layout.model.LayoutModel;

import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * Task to change the layout of the graph
 */
public class SetLayoutTask extends Task {

	private LayoutTransitionManager layoutTransitionManager;
	private String layoutName;
	private VisualizationViewer<AttributedVertex, AttributedEdge> viewer;
	private CountDownLatch taskDone = new CountDownLatch(1);

	public SetLayoutTask(VisualizationViewer<AttributedVertex, AttributedEdge> viewer,
			LayoutTransitionManager layoutTransitionManager, String layoutName) {
		super("Changing Graph Layout to " + layoutName, true, false, true, false);
		this.viewer = viewer;
		this.layoutTransitionManager = layoutTransitionManager;
		this.layoutName = layoutName;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		// add a callback for when/if the user cancels the layout, use a variable because
		// monitor uses a weak listener list and it would otherwise get garbage collected.
		CancelledListener cancelListener = this::taskCancelled;
		monitor.addCancelledListener(cancelListener);

		// add a listener so we are notified when the layout starts and ends
		VisualizationModel<AttributedVertex, AttributedEdge> model = viewer.getVisualizationModel();
		LayoutModel<AttributedVertex> layoutModel = model.getLayoutModel();
		Support support = layoutModel.getLayoutStateChangeSupport();
		Listener listener = this::layoutStateChanged;
		support.addLayoutStateChangeListener(listener);

		// start the layout - needs to be done on swing thread to prevent issues and intermediate
		// paints - should be changed in the future to not require it to be on the swing thread.
		Swing.runNow(() -> layoutTransitionManager.setLayout(layoutName));

		waitForLayoutTransition(model);

		support.removeLayoutStateChangeListener(listener);
		monitor.removeCancelledListener(cancelListener);
	}

	private void waitForLayoutTransition(
			VisualizationModel<AttributedVertex, AttributedEdge> model) {

		Graph<AttributedVertex, AttributedEdge> graph = model.getGraph();
		if (graph.vertexSet().isEmpty()) {
			// note: the underlying graph API will not notify us of the layout state change if the
			//       graph is empty, so do not wait.
			return;
		}

		// some of the layouts are done on the calling thread and some aren't. If they are on
		// the calling thread, then by now, we already got the "done" callback and the "taskDone"
		// countdown latch has been triggered and won't wait.  If, however, the layout has been
		// diverted to another thread, we want to wait until the layout is completed
		// There are two ways the latch will be triggered, the layout is completed or the user
		// cancels the layout.
		try {
			taskDone.await();
		}
		catch (InterruptedException e) {
			model.getLayoutAlgorithm().cancel();
		}

	}

	/**
	 * Notification when the layout algorithm starts and stops
	 * @param e the event. If the event.active is true, then the algorithm is starting, if false,
	 *        the algorithm is done.
	 */
	private void layoutStateChanged(Event e) {

		Msg.debug(this, "layoutStatechanged(): " + e);

		if (!e.active) {
			// algorithm is done, release the latch
			taskDone.countDown();
		}
	}

	/**
	 * Callback if the user cancels the layout
	 */
	private void taskCancelled() {

		Msg.debug(this, "taskCancelled()");

		// release the latch and tell the layout algorithm to cancel.
		taskDone.countDown();
		viewer.getVisualizationModel().getLayoutAlgorithm().cancel();
	}

}
