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

import ghidra.app.cmd.function.RemoveFunctionTagCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;

/**
 * Displays a list of tags that have been assigned to the current function
 */
public class TargetTagsPanel extends TagListPanel {

	/**
	 * Constructor
	 * 
	 * @param provider the component provider
	 * @param tool the plugin tool
	 * @param title the panel title
	 */
	public TargetTagsPanel(FunctionTagProvider provider,
			PluginTool tool, String title) {
		super(provider, tool, title);

		table.setDisabled(false);
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	@Override
	public void refresh(Function newFunction) {

		model.clear();

		this.function = newFunction;

		if (function == null) {
			setTitle("No Function Selected");
		}
		else {
			setTitle(function.getName() + " (" + function.getEntryPoint().toString() + ')');
		}

		table.setFunction(function);
		model.reload();
	}

	@Override
	protected Set<FunctionTag> backgroundLoadTags() {
		return getAssignedTags(function);
	}

	/**
	 * Removes selected tags from the currently-selected function.
	 */
	public void removeSelectedTags() {
		Set<FunctionTag> selectedTags = getSelectedTags();
		for (FunctionTag tag : selectedTags) {
			Command cmd = new RemoveFunctionTagCmd(tag.getName(), function.getEntryPoint());
			tool.execute(cmd, program);
		}
	}
}
