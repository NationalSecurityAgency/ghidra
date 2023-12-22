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
package ghidra.features.bsim.gui.search.dialog;

import ghidra.features.bsim.gui.BSimSearchPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * Dialog for initiating a BSim overview query.
 */
public class BSimOverviewDialog extends AbstractBSimSearchDialog {
	private Program program;

	public BSimOverviewDialog(PluginTool tool, BSimSearchService service,
		BSimServerManager serverManager) {
		super("BSim Overview", tool, service, serverManager);
		setOkButtonText("Overview");
		setHelpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "BSim_Overview_Dialog"));
	}

	@Override
	protected void okCallback() {
		searchService.performOverview(serverCache, getSearchSettings());
		close();
	}

	protected BSimSearchSettings getSearchSettings() {
		BSimSearchSettings lastUsed = searchService.getLastUsedSearchSettings();
		double similarity = similarityField.getValue();
		double confidence = confidenceField.getValue();
		int maxResults = lastUsed.getMaxResults();
		BSimFilterSet filterSet = lastUsed.getBSimFilterSet().copy();
		return new BSimSearchSettings(similarity, confidence, maxResults, filterSet);
	}

	public Program getProgram() {
		return program;
	}

}
