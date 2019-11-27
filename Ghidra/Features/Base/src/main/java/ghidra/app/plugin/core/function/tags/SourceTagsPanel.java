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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;

import ghidra.app.cmd.function.AddFunctionTagCmd;
import ghidra.app.cmd.function.CreateFunctionTagCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.util.Msg;
import resources.ResourceManager;

/**
 * List for displaying all tags in the program that have NOT yet been assigned
 * to a function.
 */
public class SourceTagsPanel extends TagListPanel {

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

	// List of tags read in from the external file. These will be displayed in a different 
	// color than 'regular' tags and cannot be edited or deleted, until they're added to a function
	private List<FunctionTag> tempTags = new ArrayList<>();
	
	// Keeps a list of the original temp tags as loaded from file. This is necessary
	// when switching between programs where we need to know the original state of the
	// temporary tags. Without this we would need to reload from file on each new program
	// activation.
	private List<FunctionTag> tempTagsCache;

	/**
	 * Constructor
	 * 
	 * @param provider the component provider
	 * @param tool the plugin tool
	 * @param title the title of the panel
	 */
	public SourceTagsPanel(FunctionTagsComponentProvider provider, PluginTool tool, String title) {
		super(provider, tool, title);

		// Load any tags from external sources and keep a copy in the cache
		tempTags = loadTags();		
		tempTagsCache = new ArrayList<>(tempTags);
		
		table.setDisabled(true);
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/
		
	/**
	 * Adds any selected tags to the function currently selected in the
	 * listing.
	 */
	public void addSelectedTags() {
		if (function == null) {
			return;
		}

		List<FunctionTag> selectedTags = getSelectedTags();
		for (FunctionTag tag : selectedTags) {

			// If the tag is one that has not yet been created (a temp tag), first create it,
			// then add it to the function.
			if (tag instanceof FunctionTagTemp) {
				Command cmd = new CreateFunctionTagCmd(tag.getName(), tag.getComment());
				tool.execute(cmd, program);
			}

			Command cmd = new AddFunctionTagCmd(tag.getName(), function.getEntryPoint());
			tool.execute(cmd, program);
		}
	}

	@Override
	public void refresh(Function function) {
		
		model.clear();
		
		this.function = function;

		try {
			tempTags = new ArrayList<>(tempTagsCache);
			
			List<? extends FunctionTag> dbTags = getAllTagsFromDatabase();
			for (FunctionTag tag : dbTags) {
				model.addTag(tag);
			}
			
			// Now add any temp tags. Note that this is the point at which we prune the 
			// temp tag list to remove any tags that have been added to the database. We 
			// don't do it when the command for the add has been initiated, we do it here, 
			// in response to getting the latest items from the db directly.
			Iterator<FunctionTag> iter = tempTags.iterator();
			while (iter.hasNext()) {
				FunctionTag tag = iter.next();
				Optional<? extends FunctionTag> foundTag = dbTags.stream()
																 .filter(t -> t.getName().equals(tag.getName()))
																 .findAny();
				if (foundTag.isPresent()) {
					iter.remove();
				}
				else {
					model.addTag(tag);
				}
			}
						
			model.reload();
			applyFilter();
			table.setFunction(function);
		}
		catch (IOException e) {
			Msg.error(this, "Error retrieving tags", e);
		}
	}	
	
	/**
	 * Returns true if all tags in the selection are enabled; false
	 * otherwise
	 * 
	 * @return true if all tags in the selection are enabled; false
	 * otherwise
	 */
	public boolean isSelectionEnabled() {
		List<FunctionTag> selectedTags = getSelectedTags();
		List<FunctionTag> assignedTags = getAssignedTags(function);
		if (assignedTags.containsAll(selectedTags)) {
			return false;
		}
		
		return true;
	}
	
	/******************************************************************************
	 * PRIVATE METHODS
	 ******************************************************************************/

	/**
	 * Returns an array of all tags stored in the database.
	 * 
	 * @return list of tags
	 * @throws IOException
	 */
	private List<? extends FunctionTag> getAllTagsFromDatabase() throws IOException {
		if (program == null) {
			return Collections.emptyList();
		}
		FunctionManagerDB functionManagerDB = (FunctionManagerDB) program.getFunctionManager();
		return functionManagerDB.getFunctionTagManager().getAllFunctionTags();
	}

	/**
	 * Loads tags from the external file specified.
	 * 
	 * @return the loaded tags
	 */
	private List<FunctionTag> loadTags() {
		return FunctionTagLoader.loadTags(TAG_FILE);
	}
}
