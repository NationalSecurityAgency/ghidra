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
package ghidra.framework.project.tool;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GHtmlLabel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HTMLUtilities;
import ghidra.util.layout.VerticalLayout;

public class SelectChangedToolDialog extends DialogComponentProvider {

	private final List<PluginTool> toolList;
	private boolean wasCancelled;

	private PluginTool selectedTool;

	public SelectChangedToolDialog(List<PluginTool> toolList) {
		super("Save Tool Changes?", true, false, true, false);
		this.toolList = toolList;

		addWorkPanel(buildWorkPanel());

		addOKButton();
		addCancelButton();
		Dimension preferredSize = getPreferredSize();
		setPreferredSize(preferredSize.width, Math.min(300, preferredSize.height));
		setRememberLocation(false);
		setRememberSize(false);

	}

	private JPanel buildWorkPanel() {

		JPanel panel = new JPanel(new BorderLayout());

		String toolName = toolList.get(0).getToolName();
		JLabel descriptionLabel = new GHtmlLabel(HTMLUtilities.toHTML(
			"There are multiple changed instances of " + HTMLUtilities.escapeHTML(toolName) +
				" running.<p>Which one would like to save to your tool chest?"));
		descriptionLabel.setIconTextGap(15);
		descriptionLabel.setIcon(OptionDialog.getIconForMessageType(OptionDialog.WARNING_MESSAGE));
		descriptionLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(descriptionLabel, BorderLayout.NORTH);
		JScrollPane scrollPane = new JScrollPane(buildRadioButtonPanel());
		scrollPane.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(scrollPane);
		return panel;
	}

	private JPanel buildRadioButtonPanel() {
		JPanel panel = new JPanel(new VerticalLayout(5));

		ButtonGroup buttonGroup = new ButtonGroup();

		GRadioButton noneButton = new GRadioButton("None");
		ItemListener listener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				selectedTool = null;
			}
		};
		noneButton.addItemListener(listener);
		buttonGroup.add(noneButton);
		panel.add(noneButton);

		for (final PluginTool tool : toolList) {
			GRadioButton radioButton = new GRadioButton(tool.getName());
			radioButton.addItemListener(new ItemListener() {
				@Override
				public void itemStateChanged(ItemEvent e) {
					selectedTool = tool;
				}
			});
			buttonGroup.add(radioButton);
			panel.add(radioButton);
		}

		buttonGroup.setSelected(noneButton.getModel(), true);

		return panel;
	}

	@Override
	protected void cancelCallback() {
		super.cancelCallback();
		wasCancelled = true;
	}

	@Override
	protected void okCallback() {
		close();
	}

	boolean wasCancelled() {
		return wasCancelled;
	}

	PluginTool getSelectedTool() {
		return selectedTool;
	}
}
