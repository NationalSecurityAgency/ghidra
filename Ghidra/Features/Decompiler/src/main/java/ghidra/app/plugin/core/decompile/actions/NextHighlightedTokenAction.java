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

import java.util.List;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.fieldpanel.field.Field;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.TokenIterator;
import ghidra.app.decompiler.component.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.util.HelpLocation;

/**
 * An action to navigate to the next token highlighted by the user via the middle-mouse.
 */
public class NextHighlightedTokenAction extends AbstractDecompilerAction {

	public NextHighlightedTokenAction() {
		super("Next Highlighted Token");

		setPopupMenuData(new MenuData(new String[] { "Next Highlight" }, "Decompile"));
		setKeyBindingData(new KeyBindingData("Ctrl period"));
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "GoToMiddleMouseHighlight"));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		if (!context.hasRealFunction()) {
			return false;
		}
		DecompilerPanel panel = context.getDecompilerPanel();
		TokenHighlights highlights = panel.getMiddleMouseHighlights();
		if (highlights != null) {
			return highlights.size() > 1;
		}
		return false;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {

		DecompilerPanel panel = context.getDecompilerPanel();
		TokenHighlights highlights = panel.getMiddleMouseHighlights();
		ClangToken cursorToken = context.getTokenAtCursor();
		TokenIterator it = new TokenIterator(cursorToken, true);
		it.next(); // ignore the current token

		if (goToNexToken(panel, it, highlights)) {
			return; // found another token in the current direction
		}

		// this means there are no more occurrences in the current direction; wrap the search
		ClangToken firstToken = getFirstToken(panel);
		it = new TokenIterator(firstToken, true);
		goToNexToken(panel, it, highlights);
	}

	private ClangToken getFirstToken(DecompilerPanel panel) {
		List<Field> fields = panel.getFields();
		Field line = fields.get(0);
		ClangTextField tf = (ClangTextField) line;
		return tf.getFirstToken();
	}

	private boolean goToNexToken(DecompilerPanel panel, TokenIterator it,
			TokenHighlights highlights) {

		while (it.hasNext()) {
			ClangToken nextToken = it.next();
			HighlightToken hlToken = highlights.get(nextToken);
			if (hlToken == null) {
				continue;
			}

			ClangToken token = hlToken.getToken();
			panel.goToToken(token);
			return true;
		}

		return false;
	}
}
