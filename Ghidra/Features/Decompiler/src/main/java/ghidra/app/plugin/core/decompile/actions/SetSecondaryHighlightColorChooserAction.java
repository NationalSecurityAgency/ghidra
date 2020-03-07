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
import java.util.List;

import docking.action.MenuData;
import docking.options.editor.GhidraColorChooser;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.TokenHighlightColors;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;

public class SetSecondaryHighlightColorChooserAction extends AbstractSetSecondaryHighlightAction {

	public static String NAME = "Set Secondary Highlight With Color";

	public SetSecondaryHighlightColorChooserAction() {
		super(NAME);

		setPopupMenuData(
			new MenuData(new String[] { "Secondary Highlight", "Set Highlight..." }, "Decompile"));
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {

		ClangToken token = context.getTokenAtCursor();
		DecompilerPanel panel = context.getDecompilerPanel();
		TokenHighlightColors colors = panel.getSecondaryHighlightColors();
		List<Color> recentColors = colors.getRecentColors();

		String name = token.getText();
		Color currentColor = colors.getColor(name);
		GhidraColorChooser chooser = new GhidraColorChooser(currentColor);
		chooser.setColorHistory(recentColors);
		chooser.setActiveTab("RGB");

		Color colorChoice = chooser.showDialog(null);
		if (colorChoice == null) {
			return; // cancelled
		}

		colors.setColor(name, colorChoice);
		panel.addSecondaryHighlight(token, colorChoice);
	}

}
