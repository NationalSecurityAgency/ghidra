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
package docking.theme.gui;

import java.awt.*;
import java.awt.event.*;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.theme.*;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.table.GFilterTable;
import docking.widgets.table.GTable;
import ghidra.util.Swing;
import resources.Icons;

public class GThemeDialog extends DialogComponentProvider {

	private ThemeColorTableModel colorTableModel;
	private GThemeColorEditorDialog dialog;

	public GThemeDialog() {
		super("Theme Dialog", false);
		addWorkPanel(createMainPanel());
		addOKButton();
		addCancelButton();
		setOkButtonText("Save");
		setPreferredSize(1100, 500);
		setRememberSize(false);

	}

	@Override
	protected void okCallback() {
		for (Window window : Window.getWindows()) {
			SwingUtilities.updateComponentTreeUI(window);
		}

//		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
//		chooser.setTitle("Choose Theme File");
//		chooser.setApproveButtonText("Select Output File");
//		chooser.setApproveButtonToolTipText("Select File");
//		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
//		chooser.setSelectedFileFilter(GhidraFileFilter.ALL);
//		File file = chooser.getSelectedFile();
//		try {
//			Gui.getActiveTheme().saveToFile(file, Gui.getAllDefaultValues());
//		}
//		catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
	}

	private JComponent createMainPanel() {
		JPanel panel = new JPanel();

		panel.setLayout(new BorderLayout());
		panel.add(buildControlPanel(), BorderLayout.NORTH);
		panel.add(buildTabedTables());
		return panel;
	}

	private Component buildControlPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
//		panel.add(buildThemeChoiceButtons(), BorderLayout.WEST);
		panel.add(buildThemeCombo(), BorderLayout.WEST);
		panel.add(buildReloadDefaultsButton(), BorderLayout.EAST);

		return panel;
	}

	private Component buildReloadDefaultsButton() {
		JButton button = new JButton(Icons.REFRESH_ICON);
		button.addActionListener(this::reloadThemeDefaults);
		button.setToolTipText("Reload Theme Defaults");
		return button;
	}

	private Component buildThemeCombo() {
		JPanel panel = new JPanel();
		Set<GTheme> supportedThemes = Gui.getSupportedThemes();
		List<String> themeNames =
			supportedThemes.stream().map(t -> t.getName()).collect(Collectors.toList());
		Collections.sort(themeNames);

		GhidraComboBox<String> combo = new GhidraComboBox<>(themeNames);
		combo.setSelectedItem(Gui.getActiveTheme().getName());
		combo.addItemListener(this::themeComboChanged);

		panel.add(new JLabel("Theme: "), BorderLayout.WEST);
		panel.add(combo);
		panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
		return panel;
	}

	private Component buildThemeChoiceButtons() {
		JPanel panel = new JPanel(new FlowLayout());
		panel.add(createThemeButton("Flat"));
		panel.add(createThemeButton("Dark Flat"));
		panel.add(createThemeButton("Metal"));
		panel.add(createThemeButton("Nimbus"));
		panel.add(createThemeButton("GDK+"));
		panel.add(createThemeButton("CDE/Motif"));
		return panel;
	}

	private JButton createThemeButton(String name) {
		JButton button = new JButton(name);
		button.addActionListener(e -> Gui.setTheme(Gui.getTheme(name)));
		return button;
	}

	private Component buildTabedTables() {
		JTabbedPane tabbedPane = new JTabbedPane();
		tabbedPane.add("Colors", buildColorTable());
		return tabbedPane;
	}

	private JComponent buildColorTable() {
		colorTableModel = new ThemeColorTableModel();

		GFilterTable<ColorValue> filterTable = new GFilterTable<>(colorTableModel);
		GTable table = filterTable.getTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					ColorValue colorValue = filterTable.getSelectedRowObject();
					if (colorValue != null) {
						editColor(colorValue);
					}
					e.consume();
				}
			}
		});

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					ColorValue value = filterTable.getItemAt(e.getPoint());
					editColor(value);
				}
			}
		});

		return filterTable;
	}

	private void themeComboChanged(ItemEvent e) {
		if (e.getStateChange() == ItemEvent.SELECTED) {
			String themeName = (String) e.getItem();
			Swing.runLater(() -> Gui.setTheme(Gui.getTheme(themeName)));
			Swing.runLater(() -> colorTableModel.reload());
		}
	}

	private void reloadThemeDefaults(ActionEvent e) {
		Gui.reloadThemeDefaults();
		colorTableModel.reload();
	}

	protected void editColor(ColorValue value) {
		if (dialog == null) {
			dialog = new GThemeColorEditorDialog(this);
		}
		dialog.editColor(value);
	}

	void colorChangeAccepted() {
		colorTableModel.reload();
	}

	void colorEditorClosed() {
		dialog = null;
	}

}
