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

import java.awt.Color;
import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.HelpLocation;

public class ToggleSecondaryHighlightAction extends AbstractDecompilerAction {

	public static String NAME = "Highlight Token";

	public ToggleSecondaryHighlightAction() {
		super(NAME);

		setPopupMenuData(new MenuData(new String[] { "Highlight Toggle" }, "Decompile"));

		// TODO new key binding: 'h'
		// TODO how about mouse actions?
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_C, 0));

		// TODO new help
		setHelpLocation(new HelpLocation(HelpTopics.SELECTION, getName()));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		if (!context.hasRealFunction()) {
			return false;
		}

		DecompilerPanel panel = context.getDecompilerPanel();
		ClangToken tokenAtCursor = panel.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}

		//
		// TODO Deal Breaker??   How to disable this action for Diff Decompilers??  
		// 	
		// 		OR, just let it work
		//

		HighVariable variable = tokenAtCursor.getHighVariable();

		// TODO does not work if behind a variable name; works in front

		// TODO restrict to variable, or allow any text?
		return variable != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {

		DecompilerPanel panel = context.getDecompilerPanel();
		TokenHighlights highlights = panel.getHighlightedTokens();
		ClangToken tokenAtCursor = panel.getTokenAtCursor();
		String text = tokenAtCursor.getText();

		// toggle the highlight
		HighlightToken highlight = highlights.get(tokenAtCursor);
		if (highlight == null) {
			// TODO maybe move this to a 'createHighlight()' method on the highlights
			Color highlightColor = highlights.getColor(text);
			HighlightToken newHiglight = new HighlightToken(tokenAtCursor, highlightColor);
			highlights.add(highlight);
			panel.tokenHighlightsAdded(newHiglight);
		}
		else {
			highlights.remove(highlight);
			panel.tokenHighlightsRemoved(highlight);

		}
	}
}
