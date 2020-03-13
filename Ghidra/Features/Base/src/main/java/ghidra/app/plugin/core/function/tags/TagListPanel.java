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

import javax.swing.*;

import docking.DockingWindowManager;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.InputDialog;
import ghidra.app.cmd.function.ChangeFunctionTagCmd;
import ghidra.app.cmd.function.DeleteFunctionTagCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;

/**
 * Base panel for displaying tags in the function tag window. 
 */
public abstract class TagListPanel extends JPanel {

	protected Program program;
	protected Function function;
	protected FunctionTagTable table;
	protected PluginTool tool;
	protected String filterString = "";
	protected FunctionTagTableModel model;
	protected FunctionTagTableModel filteredModel;
	private JLabel titleLabel;

	/**
	 * Constructor 
	 * 
	 * @param provider the display provider
	 * @param tool the plugin tool
	 * @param title the title of the panel
	 */
	public TagListPanel(FunctionTagsComponentProvider provider, PluginTool tool, String title) {
		this.tool = tool;

		setLayout(new BorderLayout());

		model = new FunctionTagTableModel("", provider.getTool());
		filteredModel = new FunctionTagTableModel("", provider.getTool());

		table = new FunctionTagTable(filteredModel);
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

				FunctionTagTable table = (FunctionTagTable) evt.getSource();

				if (evt.getClickCount() == 2) {
					int row = table.getSelectedRow();
					int nameCol = table.getColumnModel().getColumnIndex("Name");
					String tagName = (String) table.getValueAt(row, nameCol);
					FunctionTagTableModel model = (FunctionTagTableModel) table.getModel();
					FunctionTag tag = model.getTag(tagName);
					if (tag == null) {
						return;
					}

					// If the tag is a temporary one, it's not editable. Show a message to the user.
					if (tag instanceof FunctionTagTemp) {
						Msg.showWarn(this, table, "Tag Not Editable",
							"Tag " + "\"" + tag.getName() + "\"" +
								" must be added to the program before it can be modified/deleted");
						return;
					}

					String[] labels = new String[] { "Name:", "Comment:" };
					String[] init = new String[] { tag.getName(), tag.getComment() };

					InputDialog dialog = new InputDialog("Edit Tag", labels, init, true, d -> {
						String[] results = d.getValues();

						if (results == null || results.length != 2) {
							Msg.error(this, "Error retrieving data from edit dialog"); // shouldn't happen
							return false;
						}

						String newName = results[0].trim();
						String newComment = results[1].trim();

						// If the name is empty, show a warning and don't allow it. A user should 
						// never want to do this.
						if (newName.isEmpty()) {
							Msg.showWarn(this, table, "Empty Tag Name?",
								"Tag name cannot be empty");
							return false;
						}

						// Only process the name edit if the name actually changed.
						if (!newName.equals(tag.getName())) {
							Command cmd = new ChangeFunctionTagCmd(tag.getName(), newName,
								ChangeFunctionTagCmd.TAG_NAME_CHANGED);
							tool.execute(cmd, program);
						}

						// Only process the comment edit if the comment actually changed.
						if (!newComment.equals(tag.getComment())) {
							Command cmd = new ChangeFunctionTagCmd(tag.getName(), newComment,
								ChangeFunctionTagCmd.TAG_COMMENT_CHANGED);
							tool.execute(cmd, program);
						}
						return true;
					});

					DockingWindowManager.showDialog(tool.getActiveWindow(), dialog);

					if (dialog.isCanceled()) {
						return;
					}
				}
			}
		});

		titleLabel = new JLabel(title);
		titleLabel.setBorder(BorderFactory.createEmptyBorder(3, 5, 0, 0));
		add(titleLabel, BorderLayout.NORTH);
		add(new JScrollPane(table), BorderLayout.CENTER);
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	/**
	 * Clears the list and repopulates it with a new data set. Clients should override this
	 * to retrieve data for the given function.
	 * 
	 * @param function the currently selected function in the listing
	 */
	public abstract void refresh(Function function);

	public void clearSelection() {
		table.clearSelection();
	}

	public void setProgram(Program program) {
		this.program = program;
		model.setProgram(program);
		filteredModel.setProgram(program);
	}

	public void setFilterText(String text) {
		filterString = text;
		applyFilter();
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
		return model.isTagInModel(name);
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
		int[] selectedRows = table.getSelectedRows();
		int nameCol = table.getColumnModel().getColumnIndex("Name");
		for (int selectedRow : selectedRows) {
			String tagName = (String) table.getValueAt(selectedRow, nameCol);
			FunctionTag tag = filteredModel.getTag(tagName);
			if (tag instanceof FunctionTagTemp) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Deletes any selected tags from the system. 
	 */
	protected void deleteSelectedTags() {

		List<FunctionTag> selectedTags = getSelectedTags();

		if (selectedTags.isEmpty()) {
			return;
		}

		// Show a confirmation message - users may not be aware that deleting a tag is more
		// than just removing it from a function.
		int option = OptionDialog.showOptionDialog(this, "Function Tag Delete",
			"Are you sure? \nThis will delete the tag from all functions in the program.", "OK",
			OptionDialog.WARNING_MESSAGE);

		switch (option) {
			case OptionDialog.OPTION_ONE:
				for (FunctionTag tag : selectedTags) {
					Command cmd = new DeleteFunctionTagCmd(tag.getName());
					tool.execute(cmd, program);
				}
				break;
			case OptionDialog.CANCEL_OPTION:
				// do nothing
				break;
		}
	}

	/**
	 * Filters the list with the current filter settings
	 */
	protected void applyFilter() {
		filteredModel.clear();

		for (FunctionTag tag : model.getTags()) {
			if (filterString.isEmpty()) {
				filteredModel.addTag(tag);
			}
			else if (tag.getName().toLowerCase().contains(filterString.toLowerCase())) {
				filteredModel.addTag(tag);
			}
		}

		filteredModel.reload();
	}

	/**
	 * Retrieves all tags that have been assigned to the given function
	 * 
	 * @param func the function to get tags for
	 * @return list of all tags assigned to this function
	 */
	protected List<FunctionTag> getAssignedTags(Function func) {
		List<FunctionTag> assignedTags = new ArrayList<>();
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
	protected List<FunctionTag> getSelectedTags() {
		List<FunctionTag> tags = new ArrayList<>();
		int[] selectedIndices = table.getSelectedRows();
		for (int i : selectedIndices) {
			String tagName = (String) filteredModel.getValueAt(i, 0);
			Optional<FunctionTag> tag =
				filteredModel.getTags().stream().filter(t -> t.getName().equals(tagName)).findAny();
			if (tag.isPresent()) {
				tags.add(tag.get());
			}
		}

		return tags;
	}
}
