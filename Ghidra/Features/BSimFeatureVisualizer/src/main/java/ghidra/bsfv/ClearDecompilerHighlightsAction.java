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
package ghidra.bsfv;

import java.awt.Color;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.decompiler.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

/**
 * This action is used to remove any decompiler highlights added by the
 *  {@BSimFeatureVisualizerPlugin}.
 */
public class ClearDecompilerHighlightsAction extends DockingAction {
	BSimFeatureVisualizerPlugin plugin;

	public ClearDecompilerHighlightsAction(BSimFeatureVisualizerPlugin plugin) {
		super("Clear Decompiler Highlights", plugin.getName());
		this.plugin = plugin;
		this.setToolBarData(new ToolBarData(Icons.DELETE_ICON));
		setDescription("Remove decompiler highlights");
		setHelpLocation(new HelpLocation(plugin.getName(), "Removing_Decompiler_Highlights"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		clearHighlights();
	}

	/**
	 * Clears any decompiler highlights associated with {@link BSimFeatureVisualizerPlugin}.
	 */
	void clearHighlights() {
		DecompilerHighlightService service =
			plugin.getTool().getService(DecompilerHighlightService.class);
		if (service == null) {
			Msg.showError(this, null, "DecompilerHighlightService not found",
				"DecompilerHighlightService not found.");
			return;
		}
		DecompilerHighlighter highlighter = service.createHighlighter(
			HighlightAndGraphAction.BSIM_FEATURE_HIGHLIGHTER_NAME, new ClearingHighlightMatcher());
		highlighter.applyHighlights();
	}

	private class ClearingHighlightMatcher implements CTokenHighlightMatcher {
		@Override
		public Color getTokenHighlight(ClangToken token) {
			return null;
		}
	}

}
