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
package ghidra.feature.vt.gui.filters;

import java.awt.*;
import java.awt.event.*;
import java.util.*;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.list.GListCellRenderer;
import ghidra.feature.vt.api.main.VTMatchTag;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.editors.TagEditorDialog;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.framework.plugintool.PluginTool;

public class TagFilterEditorDialog extends DialogComponentProvider implements TagFilterChooser {

	private Map<String, VTMatchTag> allTags;
	private Map<String, VTMatchTag> excludedTags;
	private TagListModel listModel;
	private final VTController controller;

	public TagFilterEditorDialog(VTController controller) {
		super("Tag Chooser", true, false, true, false);
		this.controller = controller;

		setPreferredSize(300, 400); // setup a decent size
		addOKButton();
	}

	private JPanel createWorkPanel() {
		JPanel mainPanel = new JPanel(new BorderLayout());

		JScrollPane scrollPane = new JScrollPane();
		listModel = new TagListModel(allTags, excludedTags);
		final JList list = new JList(listModel);
		list.setBackground(scrollPane.getBackground());
		list.setCellRenderer(new TagRenderer());
		list.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		list.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				int index = list.locationToIndex(e.getPoint());
				Rectangle cellBounds = list.getCellBounds(index, index);
				if (cellBounds == null) {
					return;
				}
				if (cellBounds.contains(e.getPoint())) {
					TagInfo info = (TagInfo) listModel.get(index);
					info.setIncluded(!info.isIncluded());
					list.repaint();
				}
			}
		});

		scrollPane.setViewportView(list);
		mainPanel.add(scrollPane, BorderLayout.CENTER);

		JButton editButton = new JButton("Manage Tags");
		editButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {

				// show the editor
				TagEditorDialog dialog = new TagEditorDialog(controller.getSession());
				PluginTool tool = controller.getTool();
				tool.showDialog(dialog);

				allTags = getAllTags();

				// update our list of tags
				rebuild();
			}
		});

		JPanel editPanel = new JPanel();
		editPanel.add(editButton);

		mainPanel.add(editPanel, BorderLayout.SOUTH);

		return mainPanel;
	}

	@Override
	public Map<String, VTMatchTag> getExcludedTags(Map<String, VTMatchTag> allTagsMap,
			Map<String, VTMatchTag> currentExcludedTagsMap) {
		this.allTags = allTagsMap;
		this.excludedTags = currentExcludedTagsMap;

		rebuild();

		PluginTool tool = controller.getTool();
		tool.showDialog(this);

		int size = listModel.getSize();
		Map<String, VTMatchTag> newExcludedTags = new TreeMap<>();
		for (int i = 0; i < size; i++) {
			TagInfo info = (TagInfo) listModel.get(i);
			if (!info.isIncluded()) {
				VTMatchTag tag = info.getTag();
				newExcludedTags.put(tag.getName(), tag);
			}
		}
		return newExcludedTags;
	}

	private Map<String, VTMatchTag> getAllTags() {
		VTSession session = controller.getSession();
		if (session == null) {
			return Collections.emptyMap();
		}
		TreeMap<String, VTMatchTag> map = new TreeMap<>();

		Set<VTMatchTag> matchTags = session.getMatchTags();
		for (VTMatchTag tag : matchTags) {
			map.put(tag.getName(), tag);
		}

		map.put(VTMatchTag.UNTAGGED.getName(), VTMatchTag.UNTAGGED);

		return map;
	}

	private void rebuild() {
		removeWorkPanel();
		addWorkPanel(createWorkPanel());
	}

	@Override
	protected void okCallback() {
		close();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TagListModel extends DefaultListModel {
		TagListModel(Map<String, VTMatchTag> allTags, Map<String, VTMatchTag> excludedTags) {
			for (Map.Entry<String, VTMatchTag> entry : allTags.entrySet()) {
				boolean isExcluded = excludedTags.containsKey(entry.getKey());
				addElement(new TagInfo(entry.getValue(), !isExcluded));
			}
		}
	}

	private class TagInfo {
		private boolean isIncluded;
		private final VTMatchTag tag;

		TagInfo(VTMatchTag tag, boolean isIncluded) {
			this.tag = tag;
			this.isIncluded = isIncluded;
		}

		VTMatchTag getTag() {
			return tag;
		}

		boolean isIncluded() {
			return isIncluded;
		}

		void setIncluded(boolean isIncluded) {
			this.isIncluded = isIncluded;
		}

		String getDisplayText() {
			String name = tag.getName();
			if (tag == VTMatchTag.UNTAGGED) {
				name = tag.toString();
			}
			String status = isIncluded ? "included" : "excluded";
			return name + " (" + status + ")";
		}
	}

	private class TagRenderer extends GListCellRenderer<TagInfo> {

		private JPanel panel;
		private GCheckBox checkBox = new GCheckBox();

		@Override
		public Component getListCellRendererComponent(JList<? extends TagInfo> list, TagInfo value,
				int index, boolean isSelected, boolean cellHasFocus) {
			JLabel renderer = (JLabel) super.getListCellRendererComponent(list, value, index,
				isSelected, cellHasFocus);

			checkBox.setSelected(value.isIncluded);

			renderer.setText(value.getDisplayText());

			return getPanel(renderer);
		}

		private JPanel getPanel(JLabel renderer) {
			if (panel == null) {
				JScrollPane scrollPane = new JScrollPane();
				panel = new JPanel();

				// let our color match that of the scroll pane our list is inside of
				panel.setBackground(scrollPane.getBackground());

				panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
				panel.add(checkBox);
				panel.add(Box.createHorizontalStrut(5));
				panel.add(renderer);
			}
			return panel;
		}
	}
}
