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
package ghidra.app.plugin.core.function.tags;

import java.awt.BorderLayout;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;

import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.*;
import ghidra.util.table.GhidraTable;

/**
 * Displays all functions that are associated with the selected tag in the
 * {@link SourceTagsPanel}
 */
public class AllFunctionsPanel extends JPanel {

	private FunctionTableModel model;
	private JLabel titleLabel;
	private GhidraTable tablePanel;

	/**
	 * Constructor
	 * 
	 * @param program the current program
	 * @param provider the component provider
	 * @param title the title of the panel
	 */
	public AllFunctionsPanel(Program program, ComponentProviderAdapter provider, String title) {

		model = new FunctionTableModel(title, provider.getTool(), program, null);
		tablePanel = new GhidraTable(model);
		setLayout(new BorderLayout());

		titleLabel = new JLabel(title);
		titleLabel.setBorder(BorderFactory.createEmptyBorder(3, 5, 0, 0));

		add(titleLabel, BorderLayout.NORTH);
		add(new JScrollPane(tablePanel), BorderLayout.CENTER);

		GoToService goToService = provider.getTool().getService(GoToService.class);
		if (goToService != null) {
			tablePanel.installNavigation(goToService, goToService.getDefaultNavigatable());
		}
	}

	/**
	 * Updates the table with whatever is in the {@link #model}
	 */
	public void refresh() {
		model.fireTableDataChanged();
	}

	/**
	 * Updates the table with functions containing the selected tags given
	 * 
	 * @param selectedTags the selected function tags
	 */
	public void refresh(List<FunctionTag> selectedTags) {
		setSelectedTags(selectedTags);
	}

	/**
	 * Stores the current program
	 * 
	 * @param program the current program
	 */
	public void setProgram(Program program) {
		model.setProgram(program);
	}

	/**
	 * Updates the panel with the set of tags selected by the user. This
	 * will update the panel title and the contents of the function table.
	 * 
	 * @param tags the selected tags
	 */
	public void setSelectedTags(List<FunctionTag> tags) {
		String tagNames = tags.stream()
				.map(t -> t.getName())
				.collect(Collectors.joining(" or "))
				.toString();

		titleLabel.setText("Functions With Tag: " + tagNames);
		model.setSelectedTags(tags);
	}

	/**
	 * Returns the list of functions in the panel
	 * <p>
	 * This is only used for testing!
	 * 
	 * @return  the list of functions
	 */
	public List<Function> getFunctions() {
		return model.getFunctions();
	}

	/**
	 * Returns the functions table model
	 * 
	 * @return the functions table model
	 */
	public FunctionTableModel getTableModel() {
		return model;
	}
}
