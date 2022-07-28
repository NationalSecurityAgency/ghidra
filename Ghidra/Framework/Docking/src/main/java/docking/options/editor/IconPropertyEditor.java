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
package docking.options.editor;

import java.awt.*;
import java.beans.PropertyEditorSupport;
import java.util.*;
import java.util.List;

import javax.swing.*;

import docking.theme.gui.ProtectedIcon;
import docking.widgets.*;
import docking.widgets.label.GDLabel;
import docking.widgets.list.GListCellRenderer;
import resources.ResourceManager;
import resources.icons.ScaledImageIcon;
import resources.icons.UrlImageIcon;

public class IconPropertyEditor extends PropertyEditorSupport {
	private IconChooserPanel iconChooserPanel;

	@Override
	public Component getCustomEditor() {
		iconChooserPanel = new IconChooserPanel();
		return iconChooserPanel;
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public void setValue(Object value) {
		if (iconChooserPanel != null) {
			iconChooserPanel.setSelectedIcon((Icon) value);
		}
		doSetValue(value);
	}

	private void doSetValue(Object value) {
		if (!Objects.equals(value, getValue())) {
			super.setValue(value);
		}
	}

	private String iconToString(Icon icon) {
		if (icon instanceof UrlImageIcon urlIcon) {
			return urlIcon.getOriginalPath();
		}
		return "<Default>";
	}

	class IconChooserPanel extends JPanel {

		private GDLabel previewLabel;
		private DropDownSelectionTextField<Icon> dropDown;
		private IconDropDownDataModel dataModel;
		DropDownSelectionChoiceListener<Icon> choiceListener = t -> iconChanged(t);

		public IconChooserPanel() {
			build();
		}

		public void setSelectedIcon(Icon icon) {
			if (icon == null) {
				return;
			}
			if (!(icon instanceof UrlImageIcon)) {
				icon = new ProtectedIcon(icon);
			}
			updateDropDownDataModel(icon);
			updatePreviewLabel(icon);

//			iconTextField.addActionListener(listener);

		}

		private void updateDropDownDataModel(Icon icon) {
			Set<Icon> icons = ResourceManager.getLoadedUrlIcons();
			icons.add(icon);
			dataModel.setData(new ArrayList<>(icons));
			dropDown.setSelectedValue(icon);
		}

		private void build() {
			setLayout(new BorderLayout());
			add(buildTopPanel(), BorderLayout.NORTH);
			add(buildPreviewLabel(), BorderLayout.CENTER);
		}

		private Component buildTopPanel() {
			JPanel panel = new JPanel(new BorderLayout());
			dataModel = new IconDropDownDataModel();
			dropDown = new DropDownSelectionTextField<>(dataModel) {
				protected List<Icon> getMatchingData(String searchText) {
					if (searchText.isBlank()) {
						return ((IconDropDownDataModel) dataModel).getData();
					}
					return super.getMatchingData(searchText);
				}
			};
//			dropDown.setConsumeEnterKeyPress(false);
//			dropDown.addActionListener(e -> iconChanged());
			dropDown.addDropDownSelectionChoiceListener(choiceListener);
//			dropDown.addCellEditorListener(new CellEditorListener() {
//
//				@Override
//				public void editingStopped(ChangeEvent e) {
//					Msg.debug(this, "Stopped");
//				}
//
//				@Override
//				public void editingCanceled(ChangeEvent e) {
//					Msg.debug(this, "Cancelled");
//
//				}
//			});
			panel.add(dropDown, BorderLayout.CENTER);
//			JButton browseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
//			panel.add(browseButton, BorderLayout.EAST);
//			browseButton.addActionListener(e -> browse());
//			iconTextField.addActionListener(listener);

			return panel;
		}

//		private void iconChanged() {
//			Icon icon = dropDown.getSelectedValue();
//			Msg.debug(this, "action listener: icon changed " + icon);
//			dropDown.getSelectedValue();
//		}

		private void iconChanged(Icon icon) {
			boolean isDropDownWindowShowing = dropDown.isMatchingListShowing();
			if (!isDropDownWindowShowing) {
				updatePreviewLabel(icon);
				doSetValue(icon);
			}
		}

		private void browse() {
			//TODO
		}

		private Component buildPreviewLabel() {
			JPanel panel = new JPanel(new BorderLayout());

			previewLabel = new GDLabel("");
			previewLabel.setIcon(ResourceManager.getDefaultIcon());
//			previewLabel.setPreferredSize(new Dimension(350, 50));
			previewLabel.setHorizontalAlignment(SwingConstants.CENTER);
			previewLabel.setVerticalAlignment(SwingConstants.CENTER);
//			previewLabel.setMinimumSize(new Dimension(300, 50));
			panel.add(previewLabel, BorderLayout.CENTER);
			panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
			return panel;
		}

		private void updatePreviewLabel(Icon icon) {
			previewLabel.setIcon(icon);
			int height = icon.getIconHeight();
			int width = icon.getIconWidth();
			Dimension d = previewLabel.getSize();
			height = Math.max(d.height, height);
			width = Math.max(d.width, width);
			previewLabel.setPreferredSize(new Dimension(width, height));
			previewLabel.invalidate();
			iconChooserPanel.validate();
		}

	}

	class IconDropDownDataModel extends DefaultDropDownSelectionDataModel<Icon> {
		IconListCellRender renderer = new IconListCellRender();

		public IconDropDownDataModel() {
			super(Collections.emptyList(), IconPropertyEditor.this::iconToString);
		}

		List<Icon> getData() {
			return data;
		}

		void setData(List<Icon> icons) {
			Collections.sort(icons, comparator);
			data = icons;
		}

		@Override
		public List<Icon> getMatchingData(String searchText) {
			if (searchText.isBlank()) {
				return data;
			}
			searchText = searchText.toLowerCase();
			List<Icon> results = new ArrayList<>();
			for (Icon icon : data) {
				String name = iconToString(icon);
				if (name.toLowerCase().contains(searchText)) {
					results.add(icon);
				}
			}

			return results;

		}

		@Override
		public ListCellRenderer<Icon> getListRenderer() {
			return renderer;
		}

	}

	class IconListCellRender extends GListCellRenderer<Icon> {
		@Override
		protected String getItemText(Icon icon) {
			return iconToString(icon);
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends Icon> list, Icon icon,
				int index, boolean isSelected, boolean hasFocus) {
			JLabel label = (JLabel) super.getListCellRendererComponent(list, icon, index,
				isSelected, hasFocus);

			if (icon.getIconWidth() != 16 || icon.getIconHeight() != 16) {
				icon = new ScaledImageIcon(icon, 16, 16);
			}
			label.setIcon(icon);
			return label;
		}
	}

}
