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
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.ClangHighlightController;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;

/**
 * Sets the secondary highlight on the selected token
 * 
 * @see ClangHighlightController
 */
public class SetSecondaryHighlightAction extends AbstractSetSecondaryHighlightAction {

	public static String NAME = "Set Secondary Highlight";

	public SetSecondaryHighlightAction() {
		super(NAME);

		setPopupMenuData(
			new MenuData(new String[] { "Secondary Highlight", "Set Highlight" }, "Decompile"));
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {

		ClangToken token = context.getTokenAtCursor();
		context.getDecompilerPanel().addSecondaryHighlight(token);
	}
}
