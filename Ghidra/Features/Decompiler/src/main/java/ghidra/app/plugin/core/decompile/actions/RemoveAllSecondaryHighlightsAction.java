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
package ghidra.app.plugin.core.decompile.actions;

import docking.action.MenuData;
import ghidra.app.decompiler.component.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.util.HelpLocation;

/**
 * Removes all secondary highlights for the current function
 * 
 * @see ClangHighlightController
 */
public class RemoveAllSecondaryHighlightsAction extends AbstractDecompilerAction {

	public static final String NAME = "Remove All Secondary Highlights";

	public RemoveAllSecondaryHighlightsAction() {
		super(NAME);

		setPopupMenuData(new MenuData(
			new String[] { "Secondary Highlight", "Remove All Highlights" }, "Decompile"));
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionSecondaryHighlight"));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		if (!context.hasRealFunction()) {
			return false;
		}

		DecompilerPanel panel = context.getDecompilerPanel();
		TokenHighlights highlightedTokens = panel.getSecondaryHighlightedTokens();
		return !highlightedTokens.isEmpty();
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		DecompilerPanel panel = context.getDecompilerPanel();
		panel.removeSecondaryHighlights();
	}
}
