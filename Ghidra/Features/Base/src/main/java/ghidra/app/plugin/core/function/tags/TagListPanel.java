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
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.DockingWindowManager;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.cmd.function.ChangeFunctionTagCmd;
import ghidra.app.cmd.function.DeleteFunctionTagCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.GhidraThreadedTablePanel;

/**
 * Base panel for displaying tags in the function tag window. 
 */
public abstract class TagListPanel extends JPanel {

	protected PluginTool tool;
	protected FunctionTagProvider provider;
	protected Program program;
	protected Function function;

	protected FunctionTagTableModel model;
	protected FunctionTagTable table;
	private GhidraTableFilterPanel<FunctionTagRowObject> filterPanel;

	private JLabel titleLabel;

	/**
	 * Constructor 
	 * 
	 * @param provider the display provider
	 * @param tool the plugin tool
	 * @param title the title of the panel
	 */
	public TagListPanel(FunctionTagProvider provider, PluginTool tool, String title) {
		this.tool = tool;
		this.provider = provider;

		setLayout(new BorderLayout());

		model = new FunctionTagTableModel("Function Tags", provider.getTool(), this);
		GhidraThreadedTablePanel<FunctionTagRowObject> tablePanel =
			new GhidraThreadedTablePanel<>(model) {
				protected GTable createTable(ThreadedTableModel<FunctionTagRowObject, ?> tm) {
					return new FunctionTagTable(model);
				}
			};
		table = (FunctionTagTable) tablePanel.getTable();
		filterPanel = new GhidraTableFilterPanel<>(table, model);

		titleLabel = new JLabel(title);
		titleLabel.setBorder(BorderFactory.createEmptyBorder(3, 5, 0, 0));
		add(titleLabel, BorderLayout.NORTH);
		add(tablePanel, BorderLayout.CENTER);
		add(filterPanel, BorderLayout.SOUTH);

		table.addMouseListener(new MouseAdapter() {

			@Override
			public void mousePressed(MouseEvent e) {
				// Click events aren't reliably captured for some reason,
				// but presses are, so this is the best way to ensure that
				// user selections are handled
				provider.selectionChanged(TagListPanel.this);
			}

			// Handles the double-click event on table rows, which will bring up
			// a dialog for editing the tag name and/or comment.
			@Override
			public void mouseClicked(MouseEvent evt) {

				if (evt.getClickCount() != 2) {
					return;
				}

				int row = table.getSelectedRow();
				editRow(row);
			}
		});

	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	/**
	 * Clears the list and re-populates it with a new data set. Clients should override this
	 * to retrieve data for the given function.
	 * 
	 * @param newFunction the currently selected function in the listing
	 */
	public abstract void refresh(Function newFunction);

	protected abstract Set<FunctionTag> backgroundLoadTags();

	void editRow(int row) {

		FunctionTagRowObject rowObject = model.getRowObject(row);
		if (rowObject.isImmutable()) {
			Msg.showWarn(this, table, "Tag Not Editable",
				"Tag " + "\"" + rowObject.getName() + "\"" +
					" must be added to the program before it can be modified/deleted");
			return;
		}

		String tagName = rowObject.getName();
		String comment = rowObject.getComment();
		String[] labels = new String[] { "Name:", "Comment:" };
		String[] init = new String[] { tagName, comment };
		InputDialog dialog = new InputDialog("Edit Tag", labels, init, d -> {
			String[] results = d.getValues();
			if (results == null || results.length != 2) {
				return false;
			}

			String newName = results[0].trim();
			if (StringUtils.isBlank(newName)) {
				d.setStatusText("Tag name cannot be empty");
				return false;
			}

			if (!Objects.equals(tagName, newName)) {
				return true;
			}

			String newComment = results[1].trim();
			if (!Objects.equals(comment, newComment)) {
				return true;
			}
			return false;
		});

		DockingWindowManager.showDialog(tool.getActiveWindow(), dialog);
		String[] results = dialog.getValues();
		if (results[0] == null) {
			return; // cancelled/closed
		}

		String newName = results[0].trim();
		String newComment = results[1].trim();

		// Only process the name edit if the name actually changed.
		if (!newName.equals(tagName)) {
			Command cmd = new ChangeFunctionTagCmd(tagName, newName,
				ChangeFunctionTagCmd.TAG_NAME_CHANGED);
			tool.execute(cmd, program);
		}

		// Only process the comment edit if the comment actually changed.
		if (!newComment.equals(comment)) {
			Command cmd = new ChangeFunctionTagCmd(tagName, newComment,
				ChangeFunctionTagCmd.TAG_COMMENT_CHANGED);
			tool.execute(cmd, program);
		}
	}

	FunctionTagTableModel getModel() {
		return model;
	}

	public FunctionTagTable getTable() {
		return table;
	}

	public void clearSelection() {
		table.clearSelection();
	}

	public void setProgram(Program program) {
		this.program = program;
		model.setProgram(program);
	}

	public void setTitle(String title) {
		titleLabel.setText(title);
	}

	/**
	 * Returns true if the tag already exists in the model.
	 * 
	 * @param name the name of the tag
	 * @return true if the tag exists
	 */
	public boolean tagExists(String name) {
		return model.containsTag(name);
	}

	/******************************************************************************
	 * PROTECTED METHODS
	 ******************************************************************************/

	/**
	 * Returns true if the list in this panel has any list items selected.
	 * 
	 * @return true if the list has an item selected
	 */
	protected boolean hasSelection() {
		return table.getSelectedRowCount() != 0;
	}

	/**
	 * Returns true if at least one of the selected items in the list
	 * is immutable (a temporary non-user-defined tag that can't be edited/deleted).
	 *  
	 * @return true if list contains an immutable tag
	 */
	protected boolean isSelectionImmutable() {
		List<FunctionTagRowObject> items = filterPanel.getSelectedItems();
		return items.stream().anyMatch(row -> row.isImmutable());
	}

	/**
	 * Deletes any selected tags from the system. 
	 */
	protected void deleteSelectedTags() {

		Set<FunctionTag> selectedTags = getSelectedTags();
		if (selectedTags.isEmpty()) {
			return;
		}

		// Show a confirmation message - users may not be aware that deleting a tag is more
		// than just removing it from a function.
		int option = OptionDialog.showOptionDialog(this, "Function Tag Delete",
			"Are you sure? \nThis will delete the tag from all functions in the program.", "OK",
			OptionDialog.WARNING_MESSAGE);

		if (option == OptionDialog.OPTION_ONE) {
			for (FunctionTag tag : selectedTags) {
				Command cmd = new DeleteFunctionTagCmd(tag.getName());
				tool.execute(cmd, program);
			}
		}
	}

	/**
	 * Retrieves all tags that have been assigned to the given function
	 * 
	 * @param func the function to get tags for
	 * @return list of all tags assigned to this function
	 */
	protected Set<FunctionTag> getAssignedTags(Function func) {
		Set<FunctionTag> assignedTags = new HashSet<>();
		if (func != null) {
			assignedTags.addAll(func.getTags());
		}
		return assignedTags;
	}

	/**
	 * Returns a list of all tags selected in the list
	 * 
	 * @return the list of function tags
	 */
	protected Set<FunctionTag> getSelectedTags() {
		List<FunctionTagRowObject> items = filterPanel.getSelectedItems();
		return items.stream().map(row -> row.getTag()).collect(Collectors.toSet());
	}
}
