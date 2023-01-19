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
package ghidra.app.plugin.gui;

import java.awt.BorderLayout;
import java.util.*;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.list.ListPanel;
import generic.theme.GTheme;
import generic.theme.ThemeManager;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;

public class ThemeChooserDialog extends DialogComponentProvider {

	private ThemeManager themeManager;
	private ListPanel<GTheme> listPanel;
	private GTheme originalTheme;

	public ThemeChooserDialog(ThemeManager themeManager) {
		super("Change Theme");
		this.themeManager = themeManager;
		originalTheme = themeManager.getActiveTheme();
		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
		setRememberSize(false);
		setHelpLocation(new HelpLocation("Theming", "Switch_Theme"));
	}

	@Override
	protected void okCallback() {
		close();
	}

	protected void cancelCallback() {
		GTheme activeTheme = themeManager.getActiveTheme();
		if (activeTheme != originalTheme) {
			themeManager.setTheme(originalTheme);
		}
		close();
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 10));
		ThemeListModel model = new ThemeListModel();

		listPanel = new ListPanel<>();
		listPanel.setListModel(model);
		listPanel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		GTheme activeTheme = themeManager.getActiveTheme();
		listPanel.setSelectedValue(activeTheme);
		listPanel.addListSelectionListener(e -> selectionChanged());
		panel.add(listPanel);

		return panel;
	}

	private void selectionChanged() {
		GTheme selectedValue = listPanel.getSelectedValue();
		if (selectedValue == null) {
			return;
		}
		GTheme activeTheme = themeManager.getActiveTheme();
		if (selectedValue != activeTheme) {
			Swing.runLater(() -> themeManager.setTheme(selectedValue));
		}
	}

	private class ThemeListModel extends AbstractListModel<GTheme> {
		private List<GTheme> allThemes;

		ThemeListModel() {
			allThemes = new ArrayList<>(themeManager.getSupportedThemes());
			Collections.sort(allThemes, (t1, t2) -> t1.getName().compareTo(t2.getName()));
		}

		@Override
		public int getSize() {
			return allThemes.size();
		}

		@Override
		public GTheme getElementAt(int index) {
			return allThemes.get(index);
		}

	}
}
