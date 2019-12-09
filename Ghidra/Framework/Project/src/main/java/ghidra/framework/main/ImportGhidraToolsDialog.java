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

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;
import java.util.stream.Stream;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.DialogComponentProvider;
import docking.options.editor.ButtonPanelFactory;
import docking.tool.ToolConstants;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.list.ListPanel;
import ghidra.framework.ToolUtils;
import ghidra.framework.model.ToolTemplate;
import ghidra.util.HelpLocation;

class ImportGhidraToolsDialog extends DialogComponentProvider {

	private final static String SELECT_ALL = "Select All";
	private final static String DESELECT_ALL = "Select None";

	private ListPanel listPanel;
	private JPanel mainPanel;
	private GCheckBox[] checkboxes;
	private String[] tools;
	private JButton selectAllButton;
	private JButton deselectAllButton;
	private FrontEndTool tool;
	private boolean cancelled = false;

	/**
	 * Construct new SaveDataDiaog
	 * @param tool front end tool
	 */
	ImportGhidraToolsDialog(FrontEndTool tool) {

		super("Import Ghidra Tools", true);
		setHelpLocation(new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Import Ghidra Tools"));

		this.tool = tool;

		mainPanel = createPanel();
		addWorkPanel(mainPanel);

		addOKButton();
		addCancelButton();

		addListeners();
	}

	void showDialog() {
		clearStatusText();

		loadListData();
		tool.showDialog(this);
	}

	/**
	 * Gets called when the user clicks on the OK Action for the dialog.
	 */
	@Override
	protected void okCallback() {
		close();
	}

	/**
	 * Gets called when the user clicks on the Cancel Action for the dialog.
	 */
	@Override
	protected void cancelCallback() {
		cancelled = true;
		close();
	}

	/**
	 * Create the panel for this dialog.
	 */
	private JPanel createPanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		JPanel availableToolsPanel = new JPanel(new BorderLayout());

		//
		// Create Button Panel
		//
		selectAllButton = new JButton(SELECT_ALL);
		selectAllButton.setMnemonic('A');
		deselectAllButton = new JButton(DESELECT_ALL);
		deselectAllButton.setMnemonic('N');

		JPanel buttonPanel = ButtonPanelFactory.createButtonPanel(
			new JButton[] { selectAllButton, deselectAllButton });

		//
		// List Panel
		//
		listPanel = new ListPanel();
		listPanel.setCellRenderer(new DataCellRenderer());
		listPanel.setMouseListener(new ListMouseListener());

		// Layout Main Panel
		availableToolsPanel.add(buttonPanel, BorderLayout.EAST);
		availableToolsPanel.add(listPanel, BorderLayout.CENTER);
		availableToolsPanel.setBorder(new TitledBorder("Available Tools"));

		panel.add(availableToolsPanel, BorderLayout.CENTER);
		return panel;
	}

	/**
	 * Add listeners to the buttons.
	 */
	private void addListeners() {
		selectAllButton.addActionListener(e -> selectAll());

		deselectAllButton.addActionListener(e -> deselectAll());
	}

	/**
	 * Select all files to be saved.
	 */
	private void selectAll() {
		for (JCheckBox checkboxe : checkboxes) {
			checkboxe.setSelected(true);
		}
		listPanel.repaint();
	}

	/**
	 * Clear selected checkboxes.
	 */
	private void deselectAll() {
		for (JCheckBox checkboxe : checkboxes) {
			checkboxe.setSelected(false);
		}
		listPanel.repaint();
	}

	private void loadListData() {

		Set<ToolTemplate> defaultTools = ToolUtils.getDefaultApplicationTools();
		Set<ToolTemplate> extraTools = ToolUtils.getExtraApplicationTools();

		Stream<String> defaultToolNames = defaultTools.stream().map(ToolTemplate::getPath);
		Stream<String> extraToolNames = extraTools.stream().map(ToolTemplate::getPath);

		int elementCount = defaultTools.size() + extraTools.size();
		tools = new String[elementCount];
		checkboxes = new GCheckBox[elementCount];

		Iterator<String> itr = defaultToolNames.iterator();
		int count = 0;
		while (itr.hasNext()) {
			tools[count] = itr.next();
			checkboxes[count] = new GCheckBox(tools[count], false);
			checkboxes[count].setBackground(Color.WHITE);
			count++;
		}

		itr = extraToolNames.iterator();
		while (itr.hasNext()) {
			tools[count] = itr.next();
			checkboxes[count] = new GCheckBox(tools[count], false);
			checkboxes[count].setBackground(Color.LIGHT_GRAY);
			count++;
		}

		listPanel.refreshList(checkboxes);
	}

	public List<String> getSelectedList() {
		//return selectedList;
		ArrayList<String> ret = new ArrayList<>();
		for (JCheckBox checkboxe : checkboxes) {
			if (checkboxe.isSelected()) {
				ret.add(checkboxe.getText());
			}
		}

		return ret;
	}

	public boolean isCancelled() {
		return cancelled;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	/**
	 * Cell renderer to show the checkboxes for the changed data files.
	 */
	private class DataCellRenderer implements ListCellRenderer<JCheckBox> {

		private Font boldFont;

		@Override
		public Component getListCellRendererComponent(JList<? extends JCheckBox> list,
				JCheckBox value, int index, boolean isSelected, boolean cellHasFocus) {

			if (boldFont == null) {
				Font font = list.getFont();
				boldFont = new Font(font.getName(), font.getStyle() | Font.BOLD, font.getSize());
			}
			if (index == -1) {
				int selected = list.getSelectedIndex();
				if (selected == -1) {
					return null;
				}
				index = selected;
			}

			return checkboxes[index];
		}
	}

	/**
	 * Mouse listener to get the selected cell in the list.
	 */
	private class ListMouseListener extends MouseAdapter {

		@Override
		public void mouseClicked(MouseEvent e) {

			clearStatusText();

			@SuppressWarnings("unchecked")
			JList<JCheckBox> list = (JList<JCheckBox>) e.getSource();
			int index = list.locationToIndex(e.getPoint());
			if (index < 0) {
				return;
			}
			boolean selected = checkboxes[index].isSelected();
			checkboxes[index].setSelected(!selected);

			listPanel.repaint();
		}
	}

}
