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
package help.screenshot;

import java.awt.Dimension;

import docking.wizard.*;

class TestDummyPanelManager implements PanelManager {
	private WizardPanel panel;
	private boolean canFinish;
	private boolean hasNextPanel;
	private boolean hasPreviousPanel;
	private Dimension dimension;
	private WizardManager wizard;

	TestDummyPanelManager(WizardPanel panel, boolean canFinish, boolean hasNextPanel,
			boolean hasPreviousPanel, int width, int height) {
		this.panel = panel;
		this.canFinish = canFinish;
		this.hasNextPanel = hasNextPanel;
		this.hasPreviousPanel = hasPreviousPanel;
		this.dimension = new Dimension(width, height);
	}

	public void setPanel(WizardPanel panel) {
		this.panel = panel;
	}

	@Override
	public boolean canFinish() {
		return canFinish;
	}

	@Override
	public boolean hasNextPanel() {
		return hasNextPanel;
	}

	@Override
	public boolean hasPreviousPanel() {
		return hasPreviousPanel;
	}

	@Override
	public WizardPanel getNextPanel() {
		return panel;
	}

	@Override
	public WizardPanel getInitialPanel() {
		return panel;
	}

	@Override
	public WizardPanel getPreviousPanel() {
		return panel;
	}

	@Override
	public String getStatusMessage() {
		return null;
	}

	@Override
	public void finish() {
		// stub
	}

	@Override
	public void cancel() {
		// stub
	}

	@Override
	public void initialize() {
		// stub
	}

	@Override
	public Dimension getPanelSize() {
		return dimension;
	}

	@Override
	public void setWizardManager(WizardManager wm) {
		this.wizard = wm;
	}

	@Override
	public WizardManager getWizardManager() {
		return wizard;
	}

}
