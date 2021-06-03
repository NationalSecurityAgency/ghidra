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
package docking.widgets.tree;

import java.util.Collections;
import java.util.List;

import docking.widgets.tree.internal.InProgressGTreeNode;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 * Base class for nodes that generate their children on demand, but because generating their children
 * is slow, that operation is moved to a background thread.  While the children are being generated,
 * an {@link InProgressGTreeNode} will appear in the tree until the {@link LoadChildrenTask} has completed.
 */
public abstract class GTreeSlowLoadingNode extends GTreeLazyNode {

	/**
	 * Subclass must implement this method to generate their children. This operation will always be
	 * performed in a background thread (i.e. Not the swing thread)
	 * @param monitor a TaskMonitor for reporting progress and cancel notification.
	 * @return the list of children for this node.
	 * @throws CancelledException if the monitor is cancelled
	 */
	public abstract List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException;

	@Override
	protected final List<GTreeNode> generateChildren() {
		final GTree tree = getTree();
		if (Swing.isSwingThread()) {
			// This method is only supported on the swing thread for nodes that are currently
			// in a tree. The LoadChildrenTask only works if there is a tree
			if (tree == null) {
				return Collections.emptyList();
			}
			LoadChildrenTask loadTask = new LoadChildrenTask(tree);
			tree.runTask(loadTask);
			return CollectionUtils.asList(new InProgressGTreeNode());
		}
		return generateChildrenNow(getMonitor(tree));
	}

	@Override
	public int loadAll(TaskMonitor monitor) throws CancelledException {
		if (!isLoaded()) {
			monitor = new TreeTaskMonitor(monitor, 2);
			doSetChildren(generateChildren(new TreeTaskMonitor(monitor, 0)));
			monitor.incrementProgress(1);
		}
		return super.loadAll(monitor);
	}

	private List<GTreeNode> generateChildrenNow(TaskMonitor monitor) {
		try {
			return generateChildren(monitor);
		}
		catch (CancelledException e) {
			return null;
		}
	}

	private TaskMonitor getMonitor(GTree tree) {
		if (tree == null) {
			return TaskMonitor.DUMMY;
		}
		return tree.getThreadLocalMonitor();
	}

	private class LoadChildrenTask extends GTreeTask {

		LoadChildrenTask(GTree tree) {
			super(tree);
		}

		@Override
		public void run(TaskMonitor monitor) {
			if (isLoaded()) {
				// this means that another background thread loaded the children before we
				// had a chance to run.  Since we last left the JTree thinking there is an 
				// "in progress" node in place, we need to notify the JTree that this is no longer
				// the case.
				fireNodeStructureChanged(GTreeSlowLoadingNode.this);
				return;
			}

			long progressValue = monitor.getProgress();
			long maxValue = monitor.getMaximum();
			monitor.setMessage("Loading children");
			try {
				setChildren(generateChildren(monitor));
			}
			catch (CancelledException e) {
				if (!tree.isDisposed()) {
					runOnSwingThread(new Runnable() {
						@Override
						public void run() {
							tree.collapseAll(tree.getViewRoot());
						}
					});
				}
				doSetChildren(null);
			}
			finally {
				monitor.initialize(maxValue);
				monitor.setProgress(progressValue);
			}
		}
	}
}
