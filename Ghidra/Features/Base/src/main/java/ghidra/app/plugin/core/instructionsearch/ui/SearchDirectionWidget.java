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
package ghidra.app.plugin.core.instructionsearch.ui;

import java.awt.Component;
import java.awt.event.ActionEvent;

import javax.swing.*;

import docking.widgets.button.GRadioButton;

/**
 * Allows the user to define a custom search range for the {@link InstructionSearchDialog}.
 *
 */
public class SearchDirectionWidget extends ControlPanelWidget {

	private JRadioButton forwardRB;
	private JRadioButton backwardRB;

	public enum Direction {
		FORWARD, BACKWARD
	}

	private Direction searchDirection = Direction.FORWARD;

	private InstructionSearchDialog dialog;

	/**
	 * 
	 * @param plugin
	 * @param title
	 * @param dialog
	 */
	public SearchDirectionWidget(String title, InstructionSearchDialog dialog) {
		super(title);

		this.dialog = dialog;
	}

	public Direction getSearchDirection() {
		return this.searchDirection;
	}

	/*********************************************************************************************
	 * PROTECTED METHODS
	 ********************************************************************************************/

	/**
	 * 
	 */
	@Override
	protected JPanel createContent() {

		JPanel contentPanel = new JPanel();
		contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.X_AXIS));
		contentPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

		forwardRB = createSearchRB(new ForwardSearchAction(), "Forward",
			"When active, searches will be performed in the forward direction.");
		forwardRB.setSelected(true);
		contentPanel.add(forwardRB);

		backwardRB = createSearchRB(new BackwardSearchAction(), "Backward",
			"When active, searches will be performed in the backward direction.");
		contentPanel.add(backwardRB);

		ButtonGroup group = new ButtonGroup();
		group.add(forwardRB);
		group.add(backwardRB);

		return contentPanel;
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * Invoked when the user clicks the radio button indicating that subsequent searches should
	 * progress in the FORWARD direction.
	 */
	private class ForwardSearchAction extends AbstractAction {
		@Override
		public void actionPerformed(ActionEvent arg0) {
			searchDirection = Direction.FORWARD;

			if (dialog.getMessagePanel() != null) {
				dialog.getMessagePanel().clear();
			}
		}
	}

	/**
	 * Invoked when the user clicks the radio button indicating that subsequent searches should
	 * progress in the BACKWARD direction.
	 */
	private class BackwardSearchAction extends AbstractAction {
		@Override
		public void actionPerformed(ActionEvent arg0) {
			searchDirection = Direction.BACKWARD;

			if (dialog.getMessagePanel() != null) {
				dialog.getMessagePanel().clear();
			}
		}
	}

	/**
	 * Creates a radio button with the given attributes.
	 * 
	 * @param action
	 * @param name
	 * @param tooltip
	 * @return
	 */
	private JRadioButton createSearchRB(AbstractAction action, String name, String tooltip) {
		GRadioButton button = new GRadioButton(action);
		button.setText(name);
		button.setToolTipText(tooltip);
		button.setAlignmentX(Component.LEFT_ALIGNMENT);
		return button;
	}
}
