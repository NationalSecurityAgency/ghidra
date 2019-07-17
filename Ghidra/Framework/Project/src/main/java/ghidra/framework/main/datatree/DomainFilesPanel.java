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
package ghidra.framework.main.datatree;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.list.ListPanel;
import ghidra.framework.model.DomainFile;

/**
 * Reusable Panel that shows a list of checkboxes for each domain 
 * file in a list.
 */
class DomainFilesPanel extends JPanel {

	private List<DomainFile> fileList;
	private GCheckBox[] checkboxes;
	private ListPanel listPanel;

	/**
	 * Constructor
	 * @param fileList list of DomainFile objects
	 */
	DomainFilesPanel(List<DomainFile> fileList, String listTitle) {
		super();
		this.fileList = fileList;
		setLayout(new BorderLayout());
		setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 5));

		JPanel innerPanel = new JPanel(new BorderLayout());
		checkboxes = new GCheckBox[fileList.size()];
		for (int i = 0; i < fileList.size(); i++) {
			DomainFile df = fileList.get(i);
			checkboxes[i] = new GCheckBox(df.getPathname(), true);
			checkboxes[i].setBackground(Color.white);
		}

		//
		// List Panel
		//
		listPanel = new ListPanel();
		listPanel.setCellRenderer(new DataCellRenderer());
		listPanel.setMouseListener(new ListMouseListener());
		if (listTitle != null) {
			listPanel.setListTitle(listTitle);
		}
		// Layout Main Panel
		innerPanel.add(listPanel, BorderLayout.CENTER);

		add(innerPanel, BorderLayout.CENTER);
		listPanel.setListData(checkboxes);
		Dimension d = listPanel.getPreferredSize();
		if (d.width < 250) {
			listPanel.setPreferredSize(new Dimension(250, listPanel.getPreferredSize().height));
		}
	}

	/**
	 * Get the selected domain files.
	 */
	DomainFile[] getSelectedDomainFiles() {
		List<DomainFile> list = new ArrayList<>();
		for (int i = 0; i < checkboxes.length; i++) {
			if (checkboxes[i].isSelected()) {
				list.add(fileList.get(i));
			}
		}
		DomainFile[] files = new DomainFile[list.size()];
		return list.toArray(files);
	}

	/**
	 * Cell renderer to show the checkboxes for the changed data files.
	 */
	private class DataCellRenderer implements ListCellRenderer<JCheckBox> {

		@Override
		public Component getListCellRendererComponent(JList<? extends JCheckBox> list,
				JCheckBox value, int index, boolean isSelected, boolean cellHasFocus) {

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
			if (e.getClickCount() != 1) {
				return;
			}

			JList list = (JList) e.getSource();
			int index = list.locationToIndex(e.getPoint());
			if (index < 0) {
				return;
			}
			boolean selected = checkboxes[index].isSelected();
			checkboxes[index].setSelected(!selected);
			// The following repaint() is to get the check box state to get refreshed on the screen.
			// Prior to adding this the check box did not refresh the display of its state in the
			// list when selected multiple times in a row. It only seemed to repaint when focus 
			// was lost.
			list.repaint();
		}
	}

}
