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
package docking.theme;

import java.awt.BorderLayout;
import java.awt.Component;
import java.io.File;
import java.io.IOException;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.GFilterTable;
import docking.widgets.table.GTable;
import ghidra.util.filechooser.GhidraFileFilter;

public class GThemeDialog extends DialogComponentProvider {

	public GThemeDialog() {
		super("Theme Dialog");
		addWorkPanel(createMainPanel());
		addOKButton();
		addCancelButton();
		setOkButtonText("Save");

	}

	@Override
	protected void okCallback() {
		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
		chooser.setTitle("Choose Theme File");
		chooser.setApproveButtonText("Select Output File");
		chooser.setApproveButtonToolTipText("Select File");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setSelectedFileFilter(GhidraFileFilter.ALL);
		File file = chooser.getSelectedFile();
		try {
			Gui.getActiveTheme().saveToFile(file, Gui.getAllDefaultValues());
		}
		catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private JComponent createMainPanel() {
		JPanel panel = new JPanel();

		panel.setLayout(new BorderLayout());

		panel.add(buildTabedTables());
		return panel;
	}

	private Component buildTabedTables() {
		JTabbedPane tabbedPane = new JTabbedPane();
		tabbedPane.add("Colors", buildColorTable());
		return tabbedPane;
	}

	private JComponent buildColorTable() {
		ThemeColorTableModel colorTableModel = new ThemeColorTableModel(Gui.getActiveTheme());

		GTable colorTable = new GTable(colorTableModel);
		colorTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		GFilterTable<ColorValue> filterTable = new GFilterTable<>(colorTableModel);
		filterTable.getTable().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		return filterTable;
	}

}
