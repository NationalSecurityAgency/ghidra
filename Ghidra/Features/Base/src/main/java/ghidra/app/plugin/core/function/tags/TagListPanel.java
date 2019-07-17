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

import javax.swing.DefaultListModel;
import javax.swing.JPanel;

import docking.DockingWindowManager;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.label.GLabel;
import ghidra.app.cmd.function.ChangeFunctionTagCmd;
import ghidra.app.cmd.function.DeleteFunctionTagCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;

/**
 * Generic class for displaying {@link FunctionTag} objects in a list. 
 */
public abstract class TagListPanel extends JPanel {

	protected Program program;

	// The list object containing the tag names.
	protected FunctionTagList list;

	// Currently-selected function in the listing.
	protected Function function;

	// Model representing all tags assigned to the selected function. This is the
	// complete, unfiltered set of tags.
	protected DefaultListModel<FunctionTag> model = new DefaultListModel<>();

	// List of tags to be displayed in the panel. This is the full list with
	// filtering applied.
	protected DefaultListModel<FunctionTag> filteredModel = new DefaultListModel<>();

	protected PluginTool tool;

	protected String filterString = "";

	/**
	 * Constructor. 
	 * 
	 * @param provider the display provider
	 * @param tool the plugin tool
	 * @param title the title of the panel
	 */
	public TagListPanel(FunctionTagsComponentProvider provider, PluginTool tool, String title) {
		this.tool = tool;

		setLayout(new BorderLayout());

		// Set the model for the list to be the filtered model - we only ever want
		// to show the model that has filtering applied.
		list = new FunctionTagList(filteredModel);

		// When a selection is made in the list, tell the provider so it can update
		// the state of buttons, the other list, etc...
		list.addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				provider.selectionChanged(TagListPanel.this);
			}
		});

		// Mouse listener for handling the double-click event, which will bring up
		// a dialog for editing the tag name and/or comment.
		list.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				FunctionTagList list = (FunctionTagList) evt.getSource();
				if (evt.getClickCount() == 2) {

					FunctionTag tag = list.getSelectedValue();
					if (tag == null) {
						return;
					}

					// If the tag is a temporary one, it's not editable. Show a message to the user.
					if (tag instanceof FunctionTagTemp) {
						Msg.showWarn(list, list, "Tag Not Editable", "Tag " + "\"" + tag.getName() +
							"\"" +
							" was loaded from an external source and cannot be edited or deleted");
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
							Msg.showWarn(this, list, "Empty Tag Name?", "Tag name cannot be empty");
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

					dialog.setPreferredSize(400, 150);
					DockingWindowManager.showDialog(list, dialog);

					if (dialog.isCanceled()) {
						return;
					}
				}
			}
		});

		add(new GLabel(title), BorderLayout.NORTH);
		add(list, BorderLayout.CENTER);
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	/**
	 * Clears the list and repopulates with a new data set. Clients should override this
	 * to retrieve data for the given function.
	 * 
	 * @param function the currently selected function in the listing
	 */
	public abstract void refresh(Function function);

	public void clearSelection() {
		list.clearSelection();
	}

	public void setProgram(Program program) {
		this.program = program;
	}

	public void setFilterText(String text) {
		filterString = text;
		applyFilter();
	}

	/**
	 * Returns true if the tag already exists in the model.
	 * 
	 * @param name the name of the tag
	 * @return true if the tag exists
	 */
	public boolean tagExists(String name) {
		for (int i = 0; i < model.size(); i++) {
			FunctionTag tag = model.getElementAt(i);
			if (tag.getName().equals(name)) {
				return true;
			}
		}

		return false;
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
		return list.getSelectedIndices().length != 0;
	}

	/**
	 * Returns true if at least one of the selected items in the list
	 * is immutable (a temporary non-user-defined tag that can't be deleted).
	 *  
	 * @return true if list contains an immutable tag
	 */
	protected boolean isSelectionImmutable() {
		return list.getSelectedValuesList().stream().anyMatch(
			val -> val instanceof FunctionTagTemp);
	}

	protected void sortList() {
		List<FunctionTag> myList = Collections.list(model.elements());
		Collections.sort(myList);
		model.clear();
		for (FunctionTag tag : myList) {
			model.addElement(tag);
		}
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
	 * Filters the list with the current filter settings.
	 */
	protected void applyFilter() {
		filteredModel.clear();

		for (int i = 0; i < model.size(); i++) {
			if (model.get(i).getName().toLowerCase().contains(filterString.toLowerCase())) {
				filteredModel.addElement(model.get(i));
			}
		}
	}

	/**
	 * Retrieves all tags that have been assigned to the given function.
	 * 
	 * @return list of all tags assigned to this function
	 */
	protected List<FunctionTag> getAssignedTags(Function function) {
		List<FunctionTag> assignedTags = new ArrayList<>();
		if (function != null) {
			assignedTags.addAll(function.getTags());
		}
		return assignedTags;
	}

	/**
	 * Returns a list of all tags selected in the list.
	 * 
	 * @return the list of function tags
	 */
	protected List<FunctionTag> getSelectedTags() {
		List<FunctionTag> tags = new ArrayList<>();
		int[] selectedIndices = list.getSelectedIndices();
		for (int i : selectedIndices) {
			tags.add(filteredModel.getElementAt(i));
		}

		return tags;
	}
}
