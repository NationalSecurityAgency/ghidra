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

import java.util.Set;

import ghidra.app.cmd.function.AddFunctionTagCmd;
import ghidra.app.cmd.function.CreateFunctionTagCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;

/**
 * List for displaying all tags in the programs
 */
public class SourceTagsPanel extends TagListPanel {

	/**
	 * Constructor
	 * 
	 * @param provider the component provider
	 * @param tool the plugin tool
	 * @param title the title of the panel
	 */
	public SourceTagsPanel(FunctionTagProvider provider, PluginTool tool, String title) {
		super(provider, tool, title);

		table.setDisabled(true);
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	/**
	 * Adds any selected tags to the function currently selected in the listing
	 */
	public void addSelectedTags() {
		if (function == null) {
			return;
		}

		Set<FunctionTag> selectedTags = getSelectedTags();
		for (FunctionTag tag : selectedTags) {

			// If the tag is one that has not yet been created (a temp tag), first create it,
			// then add it to the function.
			if (tag instanceof InMemoryFunctionTag) {
				Command cmd = new CreateFunctionTagCmd(tag.getName(), tag.getComment());
				tool.execute(cmd, program);
			}

			Command cmd = new AddFunctionTagCmd(tag.getName(), function.getEntryPoint());
			tool.execute(cmd, program);
		}
	}

	@Override
	public void refresh(Function newFunction) {
		model.clear();
		this.function = newFunction;
		table.setFunction(function);
		model.reload();
	}

	@Override
	protected Set<FunctionTag> backgroundLoadTags() {
		return provider.backgroundLoadTags();
	}

	/**
	 * Returns true if all tags in the selection are enabled; false otherwise
	 * 
	 * @return true if all tags in the selection are enabled; false otherwise
	 */
	public boolean isSelectionEnabled() {
		Set<FunctionTag> selectedTags = getSelectedTags();
		Set<FunctionTag> assignedTags = getAssignedTags(function);
		if (assignedTags.containsAll(selectedTags)) {
			return false;
		}

		return true;
	}
}
