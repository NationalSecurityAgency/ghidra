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
package docking.widgets.tree;

import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

import java.util.List;

import javax.swing.SwingUtilities;

import docking.widgets.tree.tasks.GTreeLoadChildrenTask;

/**
 * Base class for GTNodes that want to use a lazy loading approach, but the loading may
 * be slow and therefor should be done in another thread.  By using SlowLoadingNode
 * nodes, you don't have to create all the nodes up front and the nodes will only
 * be created as needed.  If you extend this base class, you have to implement one
 * additional method than if you extended AbstractGTreeNode and that is
 * generateChildren(TaskMonitor monitor).
 * The generateChildren(TaskMonitor monitor) method will be called
 * automatically from a task thread when needed. While the loading is taking place,
 * An "In Progress" node will be displayed.
 */
public abstract class GTreeSlowLoadingNode extends AbstractGTreeNode {
	public abstract List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException;

	@Override
	protected final void loadChildren() {

		final GTree tree = getTree();
		if (SystemUtilities.isEventDispatchThread()) {
			if (isChildrenLoadedOrInProgress()) {
				return;
			}

			setInProgress(); // this will make isChildrenLoaded() return true for any subsequent calls.			
			if (tree != null) {
				GTreeLoadChildrenTask loadTask = new GTreeLoadChildrenTask(tree, this);
				tree.runTask(loadTask);
				return;
			}
		}

		if (isChildrenLoadedOrInProgress() && !isInProgress()) {
			return; // fully loaded
		}

		setInProgress();
		doLoadChildren(tree, getMonitor(tree));
	}

	private TaskMonitor getMonitor(GTree tree) {
		if (tree == null) {
			return TaskMonitorAdapter.DUMMY_MONITOR;
		}
		return tree.getThreadLocalMonitor();
	}

	private void doLoadChildren(final GTree tree, TaskMonitor monitor) {
		if (isChildrenLoaded()) {
			// Odd case where we have been told to load even though we are already loaded.
			// Probably in the middle of a filter job.  Need to reset the active chi
			// in any case.  Calling setChildren will effectively set the allChildren to its
			// current contents, but will also set the active children.
			setChildren(doGetAllChildren());
			return;
		}

		long progressValue = monitor.getProgress();
		long maxValue = monitor.getMaximum();
		try {
			setChildren(generateChildren(monitor));
		}
		catch (CancelledException e) {
			SystemUtilities.runSwingNow(new Runnable() {
				@Override
				public void run() {
					if (tree != null) {
						tree.collapseAll(tree.getRootNode());
					}
				}
			});
			doSetChildren(null, true);
		}
		finally {
			// restore monitor min/max/progress values to original state since we don't know
			// where we fit into the bigger progress picture.
			monitor.initialize(maxValue);
			monitor.setProgress(progressValue);

		}
	}

	@Override
	protected void swingSetChildren(List<GTreeNode> childList, boolean notify,
			boolean onlyIfInProgress) {
		// intentionally ignore 'onlyIfInProgress'
		super.swingSetChildren(childList, notify, true);
	}

	/**
	 * Note: you cannot call this method from the Swing thread, as the data may not have been 
	 * loaded.  Instead, this method should be called from a {@link GTreeTask}.
	 * 
	 * @param index The index where the node should be inserted
	 * @param node The node to insert
	 */
	@Override
	public void addNode(int index, GTreeNode node) {
		if (SwingUtilities.isEventDispatchThread()) {
			throw new AssertException(
				"You may not invoke this method on a GTReeSlowLoadingNode from the Swing thread");
		}
		super.addNode(index, node);
	}

}
