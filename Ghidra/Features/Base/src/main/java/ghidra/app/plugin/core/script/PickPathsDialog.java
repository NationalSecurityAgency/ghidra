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
package ghidra.app.plugin.core.script;

import javax.swing.JComponent;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.pathmanager.PathManager;
import docking.widgets.pathmanager.PathManagerListener;

public class PickPathsDialog extends DialogComponentProvider implements PathManagerListener {
	private JComponent parent;
	private PathManager pathMgr;
	private boolean changed = false;

	public PickPathsDialog(JComponent parent, PathManager pathMgr) {
		super("Script Directories");
		this.parent = parent;
		this.pathMgr = pathMgr;
		pathMgr.addListener(this);
		addWorkPanel(pathMgr.getComponent());
		addDismissButton();
	}

	PathManager getPathManager() {
		return pathMgr;
	}

	@Override
	public void pathMessage(String message) {
		setStatusText(message);
	}

	@Override
	public void pathsChanged() {
		changed = true;
	}

	public boolean hasChanged() {
		return changed;
	}

	void show() {
		DockingWindowManager.showDialog(parent, this);
	}

	@Override
	protected void dismissCallback() {
		pathMgr.removeListener(this);
		close();
	}

	public void dispose() {
		close();
	}

	public JComponent getParent() {
		return parent;
	}

}
