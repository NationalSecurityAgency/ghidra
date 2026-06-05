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
package ghidra.framework.main.wizard.project;

import java.awt.BorderLayout;

import javax.swing.*;

import docking.widgets.button.GRadioButton;
import ghidra.util.layout.VerticalLayout;

/**
 * Gui panel for choosing the project type in a new project wizard. Used by the
 * {@link ProjectTypeStep}.
 */
public class ProjectTypePanel extends JPanel {
	private JRadioButton sharedRB;
	private JRadioButton nonSharedRB;
	private ButtonGroup buttonGroup;

	ProjectTypePanel() {
		super(new BorderLayout());
		setBorder(ProjectWizardModel.STANDARD_BORDER);

		JPanel innerPanel = new JPanel(new VerticalLayout(10));

		nonSharedRB = new GRadioButton("Non-Shared Project", true);
		nonSharedRB.setToolTipText("Create a project that is not shared with others");

		sharedRB = new GRadioButton("Shared Project");
		sharedRB.setToolTipText("Create a project that can be shared with others");

		buttonGroup = new ButtonGroup();
		buttonGroup.add(nonSharedRB);
		buttonGroup.add(sharedRB);

		innerPanel.add(nonSharedRB);
		innerPanel.add(sharedRB);
		add(innerPanel);
	}

	boolean isSharedProject() {
		return sharedRB.isSelected();
	}
}
