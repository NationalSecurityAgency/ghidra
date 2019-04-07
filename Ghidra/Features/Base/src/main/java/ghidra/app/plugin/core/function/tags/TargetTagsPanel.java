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

import java.util.Collections;
import java.util.List;

import ghidra.app.cmd.function.RemoveFunctionTagCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;

/**
 * Displays a list of tags that have been assigned to the currently-selected
 * function in the listing. If no function is selected, the list will be 
 * empty.
 */
public class TargetTagsPanel extends TagListPanel {

	public TargetTagsPanel(FunctionTagsComponentProvider provider,
			PluginTool tool, String title) {
		super(provider, tool, title);
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	@Override
	public void refresh(Function function) {
		model.clear();

		List<FunctionTag> assignedTags = getAssignedTags(function);
		Collections.sort(assignedTags);
		for (FunctionTag tag : assignedTags) {
			model.addElement(tag);
		}

		this.function = function;

		sortList();
		applyFilter();
	}

	/**
	 * Removes selected tags from the currently-selected function.
	 */
	public void removeSelectedTags() {
		List<FunctionTag> selectedTags = getSelectedTags();
		for (FunctionTag tag : selectedTags) {
			Command cmd = new RemoveFunctionTagCmd(tag.getName(), function.getEntryPoint());
			tool.execute(cmd, program);
		}
	}
}
