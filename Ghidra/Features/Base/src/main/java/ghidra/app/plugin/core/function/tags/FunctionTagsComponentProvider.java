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

import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.widgets.label.GLabel;
import docking.widgets.textfield.HintTextField;
import ghidra.app.cmd.function.CreateFunctionTagCmd;
import ghidra.app.context.ProgramActionContext;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.*;

/**
 * Displays all the function tags in the database and identifies which ones have
 * been assigned to the currently selected function. Through this display users can:
 * <P>
 * <UL>
 * 	<LI>Create new tags</LI>
 * 	<LI>Edit tags (both name and comment)</LI>
 * 	<LI>Delete tags</LI>
 * 	<LI>Assign tags to the currently selected function</LI>
 * 	<LI>Remove tags from the currently selected function</LI> 
 * </UL>
 * This provider can be shown by right-clicking on a function and selecting the 
 * "Edit Tags" option, or by selecting the "Edit Function Tags" option from the
 * "Window" menu.
 */
public class FunctionTagsComponentProvider extends ComponentProviderAdapter
		implements DomainObjectListener {

	private Color BORDER_COLOR = Color.GRAY;

	private SourceTagsPanel sourcePanel;
	private TargetTagsPanel targetPanel;
	private FunctionTagButtonPanel buttonPanel;
	private AllFunctionsPanel allFunctionsPanel;

	private Program program;
	private JPanel mainPanel;

	private JPanel inputPanel;
	private JPanel filterPanel;
	private HintTextField tagInputTF;
	private HintTextField filterInputTF;

	private int MIN_WIDTH = 850;
	private int MIN_HEIGHT = 350;

	// The current program location selected in the listing. 
	private ProgramLocation currentLocation = null;

	// Character used as a separator when entering multiple tags in
	// the create tag entry field.
	private static String INPUT_DELIMITER = ",";

	/**
	 * Constructor
	 * 
	 * @param plugin the function tag plugin
	 * @param program the current program
	 */
	public FunctionTagsComponentProvider(FunctionTagPlugin plugin, Program program) {
		super(plugin.getTool(), "Function Tags", plugin.getName(), ProgramActionContext.class);

		setHelpLocation(new HelpLocation(plugin.getName(), plugin.getName()));
		this.program = program;
		addToTool();
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	/**
	 * Completely clears the UI and loads the tag table from scratch. Note that 
	 * the model will be completely reset based on whatever the current location is
	 * in the listing.
	 */
	public void reload() {

		SystemUtilities.runSwingLater(() -> {

			if (tagInputTF != null) {
				tagInputTF.setText("");
			}

			updateTitle(currentLocation);
			updateTagLists();
		});
	}

	@Override
	public void componentShown() {
		mainPanel = createWorkPanel();
		updateTagLists();
		updateTitle(currentLocation);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	/**
	 * Invoked when a new location has been detected in the listing. When 
	 * this happens we need to update the tag list to show what tags are assigned
	 * at the current location.
	 * 
	 * @param loc the address selected in the listing
	 */
	public void locationChanged(ProgramLocation loc) {
		currentLocation = loc;
		updateTitle(loc);
		updateTagLists();
	}

	public void programActivated(Program activatedProgram) {
		this.program = activatedProgram;

		// Add a listener so we pick up domain object change events (add/delete/remove, etc...)
		activatedProgram.addListener(this);

		updateTagLists();
	}

	public void programDeactivated(Program deactivatedProgram) {
		deactivatedProgram.removeListener(this);
		this.program = null;
	}

	/**
	 * This class needs to listen for changes to the domain object (tag create, delete, etc...)
	 * so it can update the display accordingly. 
	 * 
	 * @param ev the change event
	 */
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(ChangeManager.DOCR_FUNCTION_TAG_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_FUNCTION_TAG_CREATED) ||
			ev.containsEvent(ChangeManager.DOCR_FUNCTION_TAG_DELETED) ||
			ev.containsEvent(ChangeManager.DOCR_TAG_REMOVED_FROM_FUNCTION) ||
			ev.containsEvent(ChangeManager.DOCR_TAG_ADDED_TO_FUNCTION)) {
			reload();
		}
	}

	/******************************************************************************
	 * PRIVATE METHODS
	 ******************************************************************************/

	private void updateTitle(ProgramLocation location) {
		if (!isVisible()) {
			return;
		}

		Function function = getFunctionAtLocation(location);
		if (function == null) {
			setSubTitle("NOT A FUNCTION");
		}
		else {
			setSubTitle("");
		}
	}

	private JPanel createWorkPanel() {
		mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout());

		// BOTTOM PANEL
		JPanel bottomPanel = new JPanel();
		bottomPanel.setLayout(new BoxLayout(bottomPanel, BoxLayout.X_AXIS));
		bottomPanel.add(createInputPanel());
		bottomPanel.add(createFilterPanel());

		mainPanel.add(bottomPanel, BorderLayout.SOUTH);
		mainPanel.setPreferredSize(new Dimension(MIN_WIDTH, MIN_HEIGHT));

		// CENTER PANEL
		sourcePanel = new SourceTagsPanel(this, tool, "All Tags");
		targetPanel = new TargetTagsPanel(this, tool, "Assigned To Function");
		allFunctionsPanel = new AllFunctionsPanel(program, this, "Functions with Selected Tag");
		buttonPanel = new FunctionTagButtonPanel(sourcePanel, targetPanel);
		sourcePanel.setBorder(BorderFactory.createLineBorder(BORDER_COLOR));
		targetPanel.setBorder(BorderFactory.createLineBorder(BORDER_COLOR));
		allFunctionsPanel.setBorder(BorderFactory.createLineBorder(BORDER_COLOR));

		// If we don't set this, then the splitter won't be able to shrink the
		// target panels below the size required by its header, which can be large 
		// because of the amount of text displayed. Keep the minimum size setting on 
		// the source panel, however. That is generally small.
		targetPanel.setMinimumSize(new Dimension(0, 0));

		JPanel wrapper = new JPanel();
		wrapper.setLayout(new BoxLayout(wrapper, BoxLayout.X_AXIS));
		wrapper.add(sourcePanel);
		wrapper.add(buttonPanel);
		wrapper.add(targetPanel);

		JSplitPane splitter =
			new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, wrapper, allFunctionsPanel);

		mainPanel.add(splitter, BorderLayout.CENTER);

		splitter.setResizeWeight(0.5f);
		splitter.setDividerLocation(0.5f);

		return mainPanel;
	}

	/**
	 * Updates the button panel depending on the selection state of the
	 * tag lists. Also updates the {@link AllFunctionsPanel} so it can update
	 * its list.
	 * 
	 * @param panel the panel that generated the selection event
	 */
	public void selectionChanged(TagListPanel panel) {

		Function function = getFunctionAtLocation(currentLocation);

		if (panel instanceof SourceTagsPanel) {
			buttonPanel.sourcePanelSelectionChanged(function != null);
			targetPanel.clearSelection();
		}
		else if (panel instanceof TargetTagsPanel) {
			buttonPanel.targetPanelSelectionChanged(function != null);
			sourcePanel.clearSelection();
		}

		List<FunctionTag> sourceTags = sourcePanel.getSelectedTags();
		List<FunctionTag> targetTags = targetPanel.getSelectedTags();
		sourceTags.addAll(targetTags);
		allFunctionsPanel.setSelectedTags(sourceTags);
	}

	/**
	 * Returns the {@link Function} at the given program location. If not a function, or
	 * if the location is not a pointer to a function returns null.
	 * 
	 * @param loc the program location
	 * @return function containing the location, or null if not applicable
	 */
	private Function getFunctionAtLocation(ProgramLocation loc) {

		Address functionAddress = getFunctionAddress(loc);
		if (functionAddress == null) {
			return null;
		}

		return program.getFunctionManager().getFunctionContaining(functionAddress);
	}

	/**
	 * Retrieves the address of the function associated with the given program location.
	 * 
	 * @param loc the program location
	 * @return the entry point of the function, or null if not valid
	 */
	private Address getFunctionAddress(ProgramLocation loc) {

		if (program == null || loc == null) {
			return null;
		}

		// If the user clicks on an instruction within a function we want to show
		// the tags.
		if (program.getFunctionManager().isInFunction(loc.getAddress())) {
			return loc.getAddress();
		}

		if (loc instanceof FunctionLocation) {
			FunctionLocation functionLocation = (FunctionLocation) loc;
			Address functionAddress = functionLocation.getFunctionAddress();
			return functionAddress;
		}

		return null;
	}

	/**
	 * Refreshes the contents of the table with the current program and location. This 
	 * should be called any time a program is activated or the location in the listing
	 * has changed.
	 */
	private void updateTagLists() {

		if (sourcePanel == null || targetPanel == null || allFunctionsPanel == null) {
			return;
		}

		sourcePanel.setProgram(program);
		targetPanel.setProgram(program);
		allFunctionsPanel.setProgram(program);

		// Get the currently selected tags and use them to update the
		// all functions panel. If there is no current selection, leave the
		// table as-is.
		List<FunctionTag> sTags = sourcePanel.getSelectedTags();
		List<FunctionTag> tTags = targetPanel.getSelectedTags();
		sTags.addAll(tTags);
		if (!sTags.isEmpty()) {
			allFunctionsPanel.refresh(sTags);
		}

		Function function = getFunctionAtLocation(currentLocation);
		sourcePanel.refresh(function);
		targetPanel.refresh(function);
	}

	/**
	 * Parses all items in the text input field and adds them as new tags. 
	 */
	private void processCreates() {

		if (program == null) {
			Msg.showInfo(this, tool.getActiveWindow(), "No program!",
				"You must load a program before trying to create tags");
			return;
		}
		List<String> names = getInputNames();
		for (String name : names) {

			// Only execute the create command if a tag with the given name does not 
			// already exist.
			if (sourcePanel.tagExists(name) || targetPanel.tagExists(name)) {
				Msg.showInfo(this, tool.getActiveWindow(), "Duplicate Tag Name",
					"There is already a tag with the name [" + name + "]. Please try again.");
			}
			else {
				Command cmd = new CreateFunctionTagCmd(name);
				tool.execute(cmd, program);
			}
		}
	}

	/**
	 * Returns a list of tag names the user has entered in the input field.
	 * Note: This assumes that multiple entries are comma-delimited.
	 * 
	 * @return the list of tag names to create
	 */
	private List<String> getInputNames() {

		// First split the string on the delimiter to get all the entries.
		String[] names = tagInputTF.getText().split(INPUT_DELIMITER);

		// Trim each item to remove any leading/trailing whitespace and add to
		// the return list. 
		ArrayList<String> nameList = new ArrayList<>();
		for (String name : names) {
			if (!name.trim().isEmpty()) {
				nameList.add(name.trim());
			}
		}

		return nameList;
	}

	/**
	 * Creates a panel that allows users to enter text that will be used
	 * as a filter on the source and target lists.
	 * 
	 * @return the new filter panel
	 */
	private JPanel createFilterPanel() {
		filterPanel = new JPanel(new BorderLayout());

		filterInputTF = new HintTextField("");
		filterInputTF.setName("filterInputTF");
		filterInputTF.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent e) {
				JTextField textField = (JTextField) e.getSource();
				String text = textField.getText();
				sourcePanel.setFilterText(text);
				targetPanel.setFilterText(text);
				allFunctionsPanel.setFilterText(text);

				if (!text.isEmpty()) {
					filterInputTF.setBackground(Color.YELLOW);
				}
				else {
					filterInputTF.setBackground(Color.WHITE);
				}
			}
		});

		filterPanel.add(new GLabel(" Tag Filter:"), BorderLayout.WEST);
		filterPanel.add(filterInputTF, BorderLayout.CENTER);

		return filterPanel;
	}

	/**
	 * Creates the text-entry panel for adding new tag names.
	 * 
	 * @return the new text input panel
	 */
	private JPanel createInputPanel() {

		inputPanel = new JPanel(new BorderLayout());
		tagInputTF = new HintTextField("tag 1, tag 2, ...");
		tagInputTF.setName("tagInputTF");
		tagInputTF.addActionListener(e -> processCreates());

		inputPanel.add(new GLabel(" Create new tag(s):"), BorderLayout.WEST);
		inputPanel.add(tagInputTF, BorderLayout.CENTER);

		return inputPanel;
	}
}
