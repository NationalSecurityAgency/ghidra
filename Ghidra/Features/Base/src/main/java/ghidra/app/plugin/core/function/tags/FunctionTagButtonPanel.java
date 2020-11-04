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
package ghidra.app.plugin.core.function.tags;

import java.awt.*;
import java.awt.event.ActionListener;

import javax.swing.*;

import resources.Icons;
import resources.ResourceManager;

/**
 * Provides buttons to be used with the {@link FunctionTagProvider}.
 * These buttons allow users to add or remove tags from functions, or delete
 * tags altogether. 
 * <p>
 * This panel has knowledge of the two tag lists it manages, called "source" and
 * "target". The former contains all tags in the database, minus those already
 * assigned to the current function. The latter contains only those tags
 * assigned to the current function.
 */
public class FunctionTagButtonPanel extends JPanel {

	private Icon ADD_IMG = ResourceManager.loadImage("images/2rightarrow.png");
	private Icon REMOVE_IMG = ResourceManager.loadImage("images/2leftarrow.png");

	private SourceTagsPanel sourcePanel;
	private TargetTagsPanel targetPanel;
	private JButton addBtn;
	private JButton removeBtn;
	private JButton deleteBtn;

	/**
	 * Constructor.
	 * 
	 * @param sourcePanel the panel displaying tags not yet assigned to the current function
	 * @param targetPanel the panel displaying tags assigned to the current function
	 */
	public FunctionTagButtonPanel(SourceTagsPanel sourcePanel, TargetTagsPanel targetPanel) {
		this.sourcePanel = sourcePanel;
		this.targetPanel = targetPanel;
		createButtonPanel();
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	/**
	 * Invoked when the user has selected an item in the source panel.
	 * 
	 * @param validFunction true if a function is selected in the listing
	 */
	public void sourcePanelSelectionChanged(boolean validFunction) {

		boolean hasSelection = sourcePanel.hasSelection();
		boolean isImmutable = sourcePanel.isSelectionImmutable();
		boolean isEnabled = sourcePanel.isSelectionEnabled();

		addBtn.setEnabled(hasSelection && validFunction && isEnabled);
		removeBtn.setEnabled(false);

		if (!hasSelection) {
			sourcePanel.clearSelection();
		}

		deleteBtn.setEnabled(hasSelection && !isImmutable);
	}

	/**
	 * Invoked when the user has selected an item in the target panel.
	 * 
	 * @param validFunction true if a function is selected in the listing
	 */
	public void targetPanelSelectionChanged(boolean validFunction) {

		boolean hasSelection = targetPanel.hasSelection();
		boolean isImmutable = targetPanel.isSelectionImmutable();

		removeBtn.setEnabled(hasSelection && validFunction);
		addBtn.setEnabled(false);

		if (!hasSelection) {
			targetPanel.clearSelection();
		}

		deleteBtn.setEnabled(hasSelection && !isImmutable);
	}

	/******************************************************************************
	 * PRIVATE METHODS
	 ******************************************************************************/

	private void createButtonPanel() {
		setLayout(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();

		gbc.gridx = 0;
		gbc.gridy = 0;
		addBtn = createButton("addBtn", ADD_IMG, "Add selected tags to the function",
			e -> {
				sourcePanel.addSelectedTags();
			});
		add(addBtn, gbc);

		gbc.gridy = 1;
		removeBtn = createButton("removeBtn", REMOVE_IMG, "Remove selected tags from the function",
			e -> targetPanel.removeSelectedTags());
		add(removeBtn, gbc);

		gbc.gridy = 2;
		deleteBtn = createButton("deleteBtn", Icons.DELETE_ICON,
			"Deletes the selected tags from the program", e -> {
				sourcePanel.deleteSelectedTags();
				targetPanel.deleteSelectedTags();
			});
		add(deleteBtn, gbc);

		setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		setMaximumSize(new Dimension(30, 300));
	}

	/**
	 * Helper function for creating a button with a given action.
	 * 
	 * @param name the name of the button
	 * @param icon the icon
	 * @param tooltip the tooltip to display on hover
	 * @param action the action to execute on click
	 * @return the new button
	 */
	private JButton createButton(String name, Icon icon, String tooltip, ActionListener action) {
		JButton button = new JButton(name);
		button.setName(name);
		button.setToolTipText(tooltip);
		icon = ResourceManager.getScaledIcon(icon, 16, 16);
		button.setIcon(icon);
		button.setText("");
		button.addActionListener(action);
		return button;
	}
}
