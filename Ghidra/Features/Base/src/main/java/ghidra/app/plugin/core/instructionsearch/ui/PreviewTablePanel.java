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

import java.awt.BorderLayout;

import javax.swing.*;

import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;

/**
 * Container for the {@link PreviewTable}.
 */
public class PreviewTablePanel extends JPanel {

	private JScrollPane scrollPane;

	private PreviewTable previewTable;

	private InstructionSearchPlugin plugin;

	private int columns;
	private InstructionSearchDialog dialog;

	public PreviewTablePanel(int columns, InstructionSearchPlugin plugin,
			InstructionSearchDialog dialog) {
		this.plugin = plugin;
		this.columns = columns;
		this.dialog = dialog;
		setup();
	}

	public void buildPreview() {
		previewTable.buildPreviewStrings();
	}

	public JScrollPane getScrollPane() {
		return this.scrollPane;
	}

	public PreviewTable getTable() {
		return this.previewTable;
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	private void setup() {
		setLayout(new BorderLayout());

		previewTable = new PreviewTable(columns, plugin, dialog);
		scrollPane = new JScrollPane(previewTable);
		scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

		add(previewTable.getToolbar(), BorderLayout.NORTH);
		add(scrollPane, BorderLayout.CENTER);
	}

}
