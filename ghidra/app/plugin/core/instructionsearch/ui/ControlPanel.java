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
package ghidra.app.plugin.core.instructionsearch.ui;

import java.awt.*;

import javax.swing.BorderFactory;
import javax.swing.JPanel;

import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;

/**
 * Container for widgets that control how the {@link InstructionSearchDialog} performs 
 * its searches.
 */
public class ControlPanel extends JPanel {

	private SelectionScopeWidget rangeWidget;
	private SearchDirectionWidget directionWidget;

	/**
	 * 
	 * @param plugin
	 * @param dialog
	 */
	public ControlPanel(InstructionSearchPlugin plugin, InstructionSearchDialog dialog) {
		setLayout(new GridBagLayout());

		GridBagConstraints gbc = new GridBagConstraints();

		rangeWidget = new SelectionScopeWidget(plugin, "Selection Scope", dialog);
		rangeWidget.setVisible(true);

		directionWidget = new SearchDirectionWidget("Search Direction", dialog);
		directionWidget.setVisible(true);

		gbc.weightx = 0.0;
		gbc.weighty = 0.0;
		gbc.fill = GridBagConstraints.BOTH;

		gbc.gridx = 0;
		gbc.gridy = 0;
		this.add(rangeWidget, gbc);

		gbc.gridx = 1;
		gbc.gridy = 0;
		gbc.weightx = 1.0;
		this.add(directionWidget, gbc);

		this.setBorder(BorderFactory.createLineBorder(Color.GRAY));
	}

	/**
	 * 
	 * @return
	 */
	public SelectionScopeWidget getRangeWidget() {
		return this.rangeWidget;
	}

	/**
	 * 
	 * @return
	 */
	public SearchDirectionWidget getDirectionWidget() {
		return this.directionWidget;
	}
}
