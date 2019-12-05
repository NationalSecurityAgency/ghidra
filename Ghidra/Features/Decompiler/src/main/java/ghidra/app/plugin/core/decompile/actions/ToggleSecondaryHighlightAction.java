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
import java.util.function.Supplier;

import docking.action.MenuData;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.HelpLocation;

public class ToggleSecondaryHighlightAction extends AbstractDecompilerAction {

	public static String NAME = "Highlight Token";

	public ToggleSecondaryHighlightAction() {
		super(NAME);

		setPopupMenuData(new MenuData(new String[] { "Highlight Toggle" }, "Decompile"));

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
		ClangToken token = panel.getTokenAtCursor();
		Supplier<List<ClangToken>> lazyTokens = () -> panel.findTokensByName(token.getText());
		panel.toggleSecondaryHighlight(token, lazyTokens);
	}
}
