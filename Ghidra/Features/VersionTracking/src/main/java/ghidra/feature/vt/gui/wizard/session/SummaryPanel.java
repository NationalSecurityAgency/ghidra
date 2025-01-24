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
package ghidra.feature.vt.gui.wizard.session;

import java.awt.BorderLayout;

import javax.swing.*;

import docking.widgets.label.GDHtmlLabel;
import ghidra.util.layout.PairLayout;

public class SummaryPanel extends JPanel {
	private JLabel labelLabel;
	private JLabel summaryLabel;

	public SummaryPanel() {

		labelLabel = new GDHtmlLabel();
		summaryLabel = new GDHtmlLabel();

		JPanel mainPanel = new JPanel(new PairLayout(5, 10));
		mainPanel.add(labelLabel);
		mainPanel.add(summaryLabel);

		setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
		setLayout(new BorderLayout());
		add(mainPanel, BorderLayout.CENTER);
	}

	public void initialize(String labelText, String summaryText) {
		labelLabel.setText(labelText);
		summaryLabel.setText(summaryText);
	}

}
