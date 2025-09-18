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
package ghidra.app.plugin.core.functiongraph.mvc;

import ghidra.app.plugin.core.functiongraph.FGProvider;
import ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public class DefaultFGControllerListener implements FGControllerListener {

	private FGProvider provider;

	public DefaultFGControllerListener(FGProvider provider) {
		this.provider = provider;
	}

	@Override
	public void dataChanged() {
		provider.functionGraphDataChanged();
	}

	@Override
	public void userChangedLocation(ProgramLocation location, boolean vertexChanged) {

		boolean updateHistory = false;
		if (vertexChanged) {
			if (shouldSaveVertexChanges()) {
				// put the navigation on the history stack if we've changed nodes (this is the
				// location we are leaving)
				provider.saveLocationToHistory();
				updateHistory = true;
			}
		}

		provider.graphLocationChanged(location);

		if (updateHistory) {
			// put the new location on the history stack now that we've updated the provider
			provider.saveLocationToHistory();
		}
	}

	private boolean shouldSaveVertexChanges() {
		FunctionGraphPlugin plugin = provider.getPlugin();
		FunctionGraphOptions options = plugin.getFunctionGraphOptions();
		return options.getNavigationHistoryChoice() == NavigationHistoryChoices.VERTEX_CHANGES;
	}

	@Override
	public void userChangedSelection(ProgramSelection selection) {
		provider.graphSelectionChanged(selection);
	}

	@Override
	public void userSelectedText(String s) {
		provider.setClipboardStringContent(s);
	}

	@Override
	public void userNavigated(ProgramLocation location) {
		// Tell the provider to navigate to this location.  This will work for connected and 
		// disconnected providers.
		provider.internalGoTo(location);
	}
}
