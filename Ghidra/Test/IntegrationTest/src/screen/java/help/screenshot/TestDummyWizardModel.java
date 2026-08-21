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
import java.util.List;

import javax.swing.*;

import docking.wizard.WizardModel;
import docking.wizard.WizardStep;

/**
 * Wizard model for testing
 *
 * @param <T> the test data
 */
class TestDummyWizardModel<T> extends WizardModel<T> {
	private JPanel panel;
	private boolean canFinish;
	private boolean hasNextPanel;
	private boolean hasPreviousPanel;
	private Dimension dimension;
	private String title;

	TestDummyWizardModel(JPanel panel, boolean canFinish, boolean hasNextPanel,
			boolean hasPreviousPanel, String title, int width, int height, T data, Icon icon) {
		super("Test Wizard", data, icon);
		this.panel = panel;
		this.canFinish = canFinish;
		this.hasNextPanel = hasNextPanel;
		this.hasPreviousPanel = hasPreviousPanel;
		this.title = title;
		this.dimension = new Dimension(width, height);
	}

	@Override
	protected void addWizardSteps(List<WizardStep<T>> steps) {
		TestDummyWizardStep<T> step = new TestDummyWizardStep<>(this, panel, title);
		steps.add(step);
	}

	@Override
	public boolean canFinish() {
		return canFinish;
	}

	@Override
	public Dimension getPreferredSize() {
		return dimension;
	}

	@Override
	public boolean canGoNext() {
		return hasNextPanel;
	}

	@Override
	public boolean canGoBack() {
		return hasPreviousPanel;
	}

	@Override
	public String getStatusMessage() {
		return null;
	}

	@Override
	public boolean doFinish() {
		return true;
	}

	@Override
	public void cancel() {
		// stub
	}

	private static class TestDummyWizardStep<T> extends WizardStep<T> {
		private JPanel panel;

		TestDummyWizardStep(WizardModel<T> model, JPanel panel, String title) {
			super(model, title, null);
			this.panel = panel;

		}

		@Override
		public void initialize(T data) {
			// stub
		}

		@Override
		public boolean isValid() {
			return true;
		}

		@Override
		public boolean canFinish(T data) {
			return true;
		}

		@Override
		public void populateData(T data) {
			// stub
		}

		@Override
		public boolean apply(T data) {
			return false;
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}

}
