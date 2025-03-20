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
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.List;

import javax.swing.*;

import org.apache.commons.io.FileUtils;

import docking.theme.gui.ProtectedIcon;
import docking.widgets.*;
import docking.widgets.button.BrowseButton;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GDLabel;
import docking.widgets.list.GListCellRenderer;
import ghidra.framework.Application;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
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
		return "<Original>";
	}

	class IconChooserPanel extends JPanel {

		private static final String IMAGE_DIR = "images/";
		private static final String LAST_ICON_DIR_PREFERENCE_KEY = "IconEditor.lastDir";
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

		}

		private void updateDropDownDataModel(Icon icon) {
			Set<Icon> icons = getCoreIcons();
			icons.add(icon);
			dataModel.setData(new ArrayList<>(icons));
			dropDown.setSelectedValue(icon);
		}

		/**
		 * Returns all icons loaded by core Ghidra modules. For this use, we only want to use
		 * icons that are part of a standard distribution because if they are exported, they may
		 * not be available on import. Non-core icons can be used by picking them from the file
		 * system.
		 * @Return all icons loaded by core Ghidra modules
		 */
		private Set<Icon> getCoreIcons() {
			Set<Icon> loadedIcons = ResourceManager.getLoadedIcons();
			Set<Icon> filtered = new HashSet<>();
			for (Icon icon : loadedIcons) {
				if (isCoreIcon(icon)) {
					filtered.add(icon);
				}
			}
			return filtered;
		}

		private boolean isCoreIcon(Icon icon) {
			if (icon instanceof UrlImageIcon urlIcon) {
				String path = urlIcon.getUrl().getPath();
				if (path.contains("Ghidra/Framework")) {
					return true;
				}
				if (path.contains("Ghidra/Features")) {
					return true;
				}
				if (path.contains("Ghidra/Debug")) {
					return true;
				}
			}
			return false;
		}

		private void build() {
			setLayout(new BorderLayout());
			add(buildTopPanel(), BorderLayout.NORTH);
			add(buildPreviewLabel(), BorderLayout.CENTER);
		}

		private Component buildTopPanel() {
			JPanel panel = new JPanel(new BorderLayout());
			dataModel = new IconDropDownDataModel();
			dropDown = new DropDownSelectionTextField<>(dataModel);
			dropDown.setShowMatchingListOnEmptyText(true);
			dropDown.addDropDownSelectionChoiceListener(choiceListener);
			panel.add(dropDown, BorderLayout.CENTER);
			JButton browseButton = new BrowseButton();
			panel.add(browseButton, BorderLayout.EAST);
			browseButton.addActionListener(e -> browse());

			return panel;
		}

		private void iconChanged(Icon icon) {
			boolean isDropDownWindowShowing = dropDown.isMatchingListShowing();
			if (!isDropDownWindowShowing) {
				updatePreviewLabel(icon);
				doSetValue(icon);
			}
		}

		private void browse() {
			GhidraFileChooser chooser = new GhidraFileChooser(iconChooserPanel);
			chooser.setTitle("Import Icon");
			chooser.setApproveButtonToolTipText("Import Icon");
			chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			chooser.setSelectedFileFilter(
				ExtensionFileFilter.forExtensions("Icon Files", ".png", "gif"));
			String lastDir = Preferences.getProperty(LAST_ICON_DIR_PREFERENCE_KEY);
			if (lastDir != null) {
				chooser.setCurrentDirectory(new File(lastDir));
			}
			File file = chooser.getSelectedFile();
			if (file != null) {
				File dir = chooser.getCurrentDirectory();
				Preferences.setProperty(LAST_ICON_DIR_PREFERENCE_KEY, dir.getAbsolutePath());
				importIconFile(file);
			}
			chooser.dispose();
		}

		private void importIconFile(File file) {

			if (!isValidIcon(file)) {
				Msg.error(this, "File is not a valid icon: " + file.getAbsolutePath());
				return;
			}
			File dir = Application.getUserSettingsDirectory();
			String relativePath = IMAGE_DIR + file.getName();

			File destinationFile = new File(dir, relativePath);
			if (destinationFile.exists()) {
				int result = OptionDialog.showYesNoDialog(dropDown, "Overwrite?",
					"An icon with that name already exists.\n Do you want to overwrite it?");
				if (result == OptionDialog.NO_OPTION) {
					return;
				}
			}
			try {
				FileUtils.copyFile(file, destinationFile);
				String path = ResourceManager.EXTERNAL_ICON_PREFIX + relativePath;
				ImageIcon icon = ResourceManager.loadImage(path);
				setValue(icon);
			}
			catch (IOException e) {
				Msg.showError(this, dropDown, "Error importing file", e);
			}
		}

		private boolean isValidIcon(File file) {
			if (!file.exists()) {
				return false;
			}
			try {
				UrlImageIcon icon = new UrlImageIcon(file.getAbsolutePath(), file.toURI().toURL());
				icon.getIconWidth();
				return true;
			}
			catch (Exception e) {
				Msg.showError(this, dropDown, "Invalid Icon File",
					"The file is not a valid icon: " + file.getAbsolutePath());
				return false;
			}

		}

		private Component buildPreviewLabel() {
			JPanel panel = new JPanel(new BorderLayout());

			previewLabel = new GDLabel("");
			previewLabel.setIcon(ResourceManager.getDefaultIcon());
			previewLabel.setHorizontalAlignment(SwingConstants.CENTER);
			previewLabel.setVerticalAlignment(SwingConstants.CENTER);
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
