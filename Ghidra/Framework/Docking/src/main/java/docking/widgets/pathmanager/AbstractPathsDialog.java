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
package docking.widgets.pathmanager;

import javax.swing.JComponent;

import docking.DialogComponentProvider;

public abstract class AbstractPathsDialog extends DialogComponentProvider {

	protected final PathnameTablePanel tablePanel;

	protected AbstractPathsDialog(String title) {
		super(title);
		tablePanel = newPathnameTablePanel();
		addWorkPanel(buildWorkPanel());
		addOKButton();
		addCancelButton();
		setPreferredSize(600, 400);
		setRememberSize(false);
	}

	protected abstract String[] loadPaths();

	protected abstract void savePaths(String[] paths);

	protected abstract PathnameTablePanel newPathnameTablePanel();

	protected void reset() {
		String[] paths = loadPaths();
		tablePanel.setPaths(paths);
	}

	protected JComponent buildWorkPanel() {
		reset();
		return tablePanel;
	}

	@Override
	protected void okCallback() {
		String[] paths = tablePanel.getPaths();
		savePaths(paths);
		close();
	}
}
