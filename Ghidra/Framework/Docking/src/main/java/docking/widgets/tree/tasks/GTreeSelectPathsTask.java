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
package docking.widgets.tree.tasks;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JTree;
import javax.swing.tree.TreePath;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeTask;
import docking.widgets.tree.internal.GTreeSelectionModel;
import docking.widgets.tree.support.GTreeSelectionEvent;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import ghidra.util.task.TaskMonitor;

public class GTreeSelectPathsTask extends GTreeTask {
	private final EventOrigin origin;
	private boolean expandingDisabled;

	private final List<TreePath> paths;

	public GTreeSelectPathsTask(GTree gtree, JTree tree, List<TreePath> paths,
			GTreeSelectionEvent.EventOrigin origin) {
		super(gtree);
		this.origin = origin;
		this.paths = paths;
	}

	/**
	 * Tells the JTree to not expand paths for each selection that is set upon it.  Doing this
	 * will speed-up performance.   However, only call this when some other task is going to
	 * ensure that paths are properly expanded.
	 * 
	 * @param disabled true to disable
	 */
	public void setExpandingDisabled(boolean disabled) {
		this.expandingDisabled = disabled;
	}

	@Override
	public void run(TaskMonitor monitor) {
		monitor.setMessage("Selecting paths");
		monitor.initialize(paths.size());
		List<TreePath> translatedPaths = new ArrayList<>();
		for (TreePath path : paths) {
			if (monitor.isCancelled()) {
				return;
			}
			TreePath xPath = translatePath(path, monitor);
			if (xPath != null) {
				translatedPaths.add(xPath);
			}
			monitor.incrementProgress(1);
		}
		selectPaths(translatedPaths.toArray(new TreePath[translatedPaths.size()]), monitor);
	}

	private void selectPaths(TreePath[] treePaths, TaskMonitor monitor) {

		runOnSwingThread(() -> {
			if (monitor.isCancelled()) {
				return; // we can be cancelled while waiting for Swing to run us
			}

			boolean wasEnabled = jTree.getExpandsSelectedPaths();
			if (expandingDisabled) {
				jTree.setExpandsSelectedPaths(false);
			}

			try {
				doSelectPaths(treePaths);
			}
			finally {
				if (expandingDisabled) {
					jTree.setExpandsSelectedPaths(wasEnabled);
				}
			}
		});
	}

	private void doSelectPaths(TreePath[] treePaths) {
		GTreeSelectionModel selectionModel = tree.getGTSelectionModel();
		selectionModel.setSelectionPaths(treePaths, origin);

		if (treePaths != null && treePaths.length > 0) {
			// Scroll to the last item, as the tree will make the given path appear at the 
			// bottom of the view.  By scrolling the last item, all the selected items above
			// this one will appear in the view as well.
			jTree.scrollPathToVisible(treePaths[treePaths.length - 1]);
		}
	}

}
