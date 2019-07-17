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
package ghidra.framework.main;

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.*;

import docking.widgets.button.GRadioButton;
import docking.wizard.AbstractWizardJPanel;
import docking.wizard.PanelManager;
import ghidra.app.util.GenericHelpTopics;
import ghidra.util.HelpLocation;
import ghidra.util.layout.VerticalLayout;

/**
 * First panel shown in the New Project Wizard to get user input for what 
 * type of project to create: Shared, or not shared.
 * 
 * 
 */
class ProjectTypePanel extends AbstractWizardJPanel {

	private JRadioButton sharedRB;
	private JRadioButton nonSharedRB;
	private ButtonGroup buttonGroup;
	private PanelManager panelManager;

	ProjectTypePanel(PanelManager panelManager) {
		super();
		this.panelManager = panelManager;
		buildPanel();
		setBorder(NewProjectPanelManager.EMPTY_BORDER);
	}

	private void buildPanel() {
		JPanel innerPanel = new JPanel(new VerticalLayout(10));
		innerPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
		ItemListener listener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				panelManager.getWizardManager().validityChanged();
			}
		};

		nonSharedRB = new GRadioButton("Non-Shared Project", true);
		nonSharedRB.addItemListener(listener);
		nonSharedRB.setToolTipText("Create a project that is not shared with others");

		sharedRB = new GRadioButton("Shared Project");
		sharedRB.addItemListener(listener);
		sharedRB.setToolTipText("Create a project that can be shared with others");

		buttonGroup = new ButtonGroup();
		buttonGroup.add(nonSharedRB);
		buttonGroup.add(sharedRB);

		innerPanel.add(nonSharedRB);
		innerPanel.add(sharedRB);
		JPanel outerPanel = new JPanel();
		outerPanel.setBorder(BorderFactory.createEmptyBorder());
		outerPanel.add(innerPanel);
		add(outerPanel);
	}

	/* (non-Javadoc)
	 * @see ghidra.util.bean.wizard.WizardPanel#getTitle()
	 */
	@Override
	public String getTitle() {
		return "Select Project Type";
	}

	/* (non-Javadoc)
	 * @see ghidra.util.bean.wizard.WizardPanel#initialize()
	 */
	@Override
	public void initialize() {
		buttonGroup.remove(sharedRB);
		buttonGroup.remove(nonSharedRB);
		sharedRB.setSelected(false);
		sharedRB.setSelected(false);
		buttonGroup.add(nonSharedRB);
		buttonGroup.add(sharedRB);
	}

	/**
	 * Return true if the user has entered a valid project file
	 */
	@Override
	public boolean isValidInformation() {
		return sharedRB.isSelected() || nonSharedRB.isSelected();
	}

	/* (non-Javadoc)
	 * @see ghidra.util.bean.wizard.WizardPanel#getHelpLocation()
	 */
	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(GenericHelpTopics.FRONT_END, "SelectProjectType");
	}

	boolean isSharedProject() {
		return sharedRB.isSelected();
	}
}
