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
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.label.GLabel;
import docking.widgets.textfield.HintTextField;
import ghidra.app.cmd.function.CreateFunctionTagCmd;
import ghidra.app.context.ProgramActionContext;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.task.SwingUpdateManager;
import resources.ResourceManager;

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
public class FunctionTagProvider extends ComponentProviderAdapter
		implements DomainObjectListener {

	private Color BORDER_COLOR = Color.GRAY;

	private SourceTagsPanel sourcePanel;
	private TargetTagsPanel targetPanel;
	private FunctionTagButtonPanel buttonPanel;
	private AllFunctionsPanel allFunctionsPanel;

	private Program program;
	private JPanel mainPanel;

	private JPanel inputPanel;
	private HintTextField tagInputField;

	private int MIN_WIDTH = 850;
	private int MIN_HEIGHT = 350;

	private SwingUpdateManager updater = new SwingUpdateManager(this::doUpdate);

	// The current program location selected in the listing. 
	private ProgramLocation currentLocation = null;

	// Character used as a separator when entering multiple tags in
	// the create tag entry field.
	private static final String INPUT_DELIMITER = ",";

	/** 
	 * Optional! If there is a file with this name which can be found by the 
	 * {@link ResourceManager}, and it contains a valid list of tag names, 
	 * they will be loaded. The file must be XML with the following
	 * structure:
	 * 
	 * <tags>
	 *	<tag>
	 *		<name>TAG1</name>
	 *  	<comment>tag comment</comment>
	 *	</tag>
	 * </tags> 
	 * 
	 */
	private static String TAG_FILE = "functionTags.xml";

	// Keeps a list of the original tags as loaded from file. This is necessary when switching 
	// between programs where we need to know the original state of the disabled tags. Without 
	// this we would need to reload from file on each new program activation.
	private Set<FunctionTag> tagsFromFile;

	/**
	 * Constructor
	 * 
	 * @param plugin the function tag plugin
	 * @param program the current program
	 */
	public FunctionTagProvider(FunctionTagPlugin plugin, Program program) {
		super(plugin.getTool(), "Function Tags", plugin.getName(), ProgramActionContext.class);

		setHelpLocation(new HelpLocation(plugin.getName(), plugin.getName()));
		this.program = program;
		mainPanel = createWorkPanel();
		addToTool();
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	@Override
	public void componentShown() {
		updateView();
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
		updateView();
	}

	public void programActivated(Program activatedProgram) {
		this.program = activatedProgram;

		// Add a listener so we pick up domain object change events (add/delete/remove, etc...)
		activatedProgram.addListener(this);

		updateTagViews();
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

		if (!isVisible()) {
			return;
		}

		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
			ev.containsEvent(ChangeManager.DOCR_FUNCTION_TAG_CREATED) ||
			ev.containsEvent(ChangeManager.DOCR_FUNCTION_TAG_DELETED) ||
			ev.containsEvent(ChangeManager.DOCR_TAG_REMOVED_FROM_FUNCTION) ||
			ev.containsEvent(ChangeManager.DOCR_TAG_ADDED_TO_FUNCTION)) {
			updater.updateLater();
			return;
		}

		if (ev.containsEvent(ChangeManager.DOCR_FUNCTION_TAG_CHANGED)) {
			repaint();
		}
	}

	private void doUpdate() {
		reload();
	}

	private void reload() {
		allFunctionsPanel.refresh();

		Function function = getFunction(currentLocation);
		sourcePanel.refresh(function);
		targetPanel.refresh(function);
	}

	private void updateView() {
		updateTitle(currentLocation);
		updateTagViews();
	}

	private void repaint() {
		sourcePanel.repaint();
		targetPanel.repaint();
		allFunctionsPanel.repaint();
	}

	private void updateTitle(ProgramLocation location) {
		if (!isVisible()) {
			return;
		}

		Function function = getFunction(location);
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

		Function function = getFunction(currentLocation);

		if (panel instanceof SourceTagsPanel) {
			buttonPanel.sourcePanelSelectionChanged(function != null);
			targetPanel.clearSelection();
		}
		else if (panel instanceof TargetTagsPanel) {
			buttonPanel.targetPanelSelectionChanged(function != null);
			sourcePanel.clearSelection();
		}

		Set<FunctionTag> sourceTags = sourcePanel.getSelectedTags();
		Set<FunctionTag> targetTags = targetPanel.getSelectedTags();
		sourceTags.addAll(targetTags);
		allFunctionsPanel.setSelectedTags(sourceTags);
	}

	public AllFunctionsPanel getAllFunctionsPanel() {
		return allFunctionsPanel;
	}

	public TargetTagsPanel getTargetPanel() {
		return targetPanel;
	}

	public HintTextField getTagInputField() {
		return tagInputField;
	}

	public SourceTagsPanel getSourcePanel() {
		return sourcePanel;
	}

	public FunctionTagButtonPanel getButtonPanel() {
		return buttonPanel;
	}

	public JPanel getInputPanel() {
		return inputPanel;
	}

	/*tests*/ void pressEnterOnTagInputField() {
		processCreates();
	}

	Set<FunctionTag> backgroundLoadTags() {
		// Add any tags from the file system that are not in the db
		List<? extends FunctionTag> dbTags = getAllTagsFromDatabase();
		Set<FunctionTag> allTags = new HashSet<>(dbTags);
		allTags.addAll(getFileTags());
		return allTags;
	}

	/**
	 * Loads tags from the external file specified.
	 * 
	 * @return the loaded tags
	 */
	private Set<FunctionTag> getFileTags() {
		if (tagsFromFile == null) {
			tagsFromFile = FunctionTagLoader.loadTags(TAG_FILE);
		}
		return tagsFromFile;
	}

	/**
	 * Returns an array of all tags stored in the database.
	 * 
	 * @return list of tags
	 */
	private List<? extends FunctionTag> getAllTagsFromDatabase() {
		if (program == null) {
			return Collections.emptyList();
		}
		FunctionManagerDB functionManagerDB = (FunctionManagerDB) program.getFunctionManager();
		return functionManagerDB.getFunctionTagManager().getAllFunctionTags();
	}

	/**
	 * Returns the {@link Function} for the given program location
	 * 
	 * @param loc the program location
	 * @return function containing the location, or null if not applicable
	 */
	private Function getFunction(ProgramLocation loc) {

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

		// If the user clicks on an instruction within a function we want to show the tags
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
	 * Refreshes the contents of the tables with the current program and location
	 */
	private void updateTagViews() {

		if (mainPanel == null || !isVisible()) {
			return;
		}

		sourcePanel.setProgram(program);
		targetPanel.setProgram(program);
		allFunctionsPanel.setProgram(program);

		// Get the currently selected tags and use them to update the all functions panel. If 
		// there is no current selection, leave the table as-is.
		Set<FunctionTag> sTags = sourcePanel.getSelectedTags();
		Set<FunctionTag> tTags = targetPanel.getSelectedTags();
		sTags.addAll(tTags);
		if (!sTags.isEmpty()) {
			allFunctionsPanel.refresh(sTags);
		}

		Function function = getFunction(currentLocation);
		sourcePanel.refresh(function);
		targetPanel.refresh(function);
	}

	/**
	 * Parses all items in the text input field and adds them as new tags. 
	 */
	private void processCreates() {

		if (program == null) {
			Msg.showInfo(this, tool.getActiveWindow(), "No Program",
				"You must load a program before trying to create tags");
			return;
		}

		List<String> dropped = new ArrayList<>();
		List<String> names = getInputNames();
		for (String name : names) {

			// only execute the create command if a tag with the given name does not already exist
			// (note: this could fail if the model is not yet loaded, but this is unlikely.   The
			// only fallout is that the error message would not be shown--the database will not add
			// the tag twice.)
			if (sourcePanel.tagExists(name)) {
				dropped.add(name);
			}
			else {
				Command cmd = new CreateFunctionTagCmd(name);
				tool.execute(cmd, program);
			}
		}

		if (!dropped.isEmpty()) {
			String text = StringUtils.join(dropped, ", ");
			Msg.showInfo(this, tool.getActiveWindow(), "Duplicate Tag Names",
				"Tags aleady exist.  Ignoring the following tags: " + text);
		}

		Swing.runLater(() -> tagInputField.setText(""));
	}

	/**
	 * Returns a list of tag names the user has entered in the input` field.
	 * Note: This assumes that multiple entries are comma-delimited.
	 * 
	 * @return the list of tag names to create
	 */
	private List<String> getInputNames() {

		// first split the string on the delimiter to get all the entries
		String[] names = tagInputField.getText().split(INPUT_DELIMITER);

		// trim each item to remove any leading/trailing whitespace and add to the return list 
		List<String> nameList = new ArrayList<>();
		for (String name : names) {
			if (!StringUtils.isBlank(name)) {
				nameList.add(name.trim());
			}
		}

		return nameList;
	}

	/**
	 * Creates the text-entry panel for adding new tag names.
	 * 
	 * @return the new text input panel
	 */
	private JPanel createInputPanel() {

		tagInputField = new HintTextField("tag 1, tag 2, ...");
		tagInputField.setName("tagInputTF");
		tagInputField.addActionListener(e -> processCreates());

		inputPanel = new JPanel();
		Border outsideBorder = BorderFactory.createBevelBorder(BevelBorder.LOWERED);
		Border insideBorder = BorderFactory.createEmptyBorder(5, 2, 2, 2);
		inputPanel.setBorder(BorderFactory.createCompoundBorder(outsideBorder, insideBorder));
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.LINE_AXIS));
		inputPanel.add(new GLabel(" Create new tag(s):"), BorderLayout.WEST);
		inputPanel.add(Box.createHorizontalStrut(5));
		inputPanel.add(tagInputField, BorderLayout.CENTER);

		return inputPanel;
	}
}
