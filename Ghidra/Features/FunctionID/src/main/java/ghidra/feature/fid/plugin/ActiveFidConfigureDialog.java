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
package ghidra.feature.fid.plugin;

import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import generic.theme.GThemeDefaults;
import ghidra.feature.fid.db.FidFile;
import ghidra.util.HelpLocation;
import ghidra.util.layout.VerticalLayout;

/**
 * Dialog that allows user to choose which Fid databases are "Active".  A database must be
 * "Active" for it to be used for Fid analysis.
 */
public class ActiveFidConfigureDialog extends DialogComponentProvider {

	private List<FidFile> fidFiles;
	private List<JCheckBox> checkboxes = new ArrayList<>();

	public ActiveFidConfigureDialog(List<FidFile> fidFiles) {
		super("Select Active Fid Databases", true, false, true, false);

		this.fidFiles = new ArrayList<>(fidFiles);
		Collections.sort(fidFiles);

		addWorkPanel(buildMainPanel());
		addOKButton();
		setOkButtonText("Dismiss");
		setRememberSize(false);
		setPreferredSize(400, 400);
		setHelpLocation(new HelpLocation(FidPlugin.FID_HELP, "chooseactivemenu"));
	}

	@Override
	protected void okCallback() {
		close();
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(buildCheckboxPanelScroller(), BorderLayout.CENTER);
		panel.add(buildButtonPanel(), BorderLayout.SOUTH);
		panel.getAccessibleContext().setAccessibleName("Active Fid Configuration");
		return panel;
	}

	private Component buildButtonPanel() {
		JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton allButton = new JButton("Select All");
		JButton noneButton = new JButton("Select None");
		allButton.addActionListener(e -> selectAllCheckboxes(true));
		noneButton.addActionListener(e -> selectAllCheckboxes(false));
		allButton.getAccessibleContext().setAccessibleName("All");
		noneButton.getAccessibleContext().setAccessibleName("None");
		panel.add(allButton);
		panel.add(noneButton);
		panel.getAccessibleContext().setAccessibleName("Select All or None");
		return panel;
	}

	private void selectAllCheckboxes(boolean b) {
		for (JCheckBox jCheckBox : checkboxes) {
			jCheckBox.setSelected(b);
		}
	}

	private Component buildCheckboxPanelScroller() {
		JScrollPane scrollPane = new JScrollPane(buildCheckBoxPanel());
		scrollPane.getAccessibleContext().setAccessibleName("Checkbox Scroll");
		return scrollPane;
	}

	private Component buildCheckBoxPanel() {
		JPanel panel = new JPanel(new VerticalLayout(5));
		panel.setOpaque(true);
		panel.setBackground(GThemeDefaults.Colors.BACKGROUND);
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		for (FidFile fidFile : fidFiles) {
			GCheckBox checkbox = new GCheckBox(fidFile.getName(), fidFile.isActive());
			checkbox.setToolTipText(fidFile.getPath());
			checkbox.getAccessibleContext().setAccessibleName(fidFile.getBaseName());
			checkboxes.add(checkbox);
			checkbox.addItemListener(e -> fidFile.setActive(checkbox.isSelected()));
			panel.add(checkbox);
		}
		panel.getAccessibleContext().setAccessibleName("Checkboxes");
		return panel;
	}
}
