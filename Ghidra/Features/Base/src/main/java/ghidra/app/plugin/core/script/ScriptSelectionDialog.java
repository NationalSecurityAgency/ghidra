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
package ghidra.app.plugin.core.script;

import java.awt.*;
import java.util.LinkedList;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.list.GListCellRenderer;
import docking.widgets.searchlist.SearchList;
import docking.widgets.searchlist.SearchListEntry;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.script.ScriptInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.HTMLUtilities;
import ghidra.util.Swing;

/**
 * A dialog that prompts the user to select a script from a searchable list
 * organized into "Recent Scripts" and "All Scripts" categories.
 */
public class ScriptSelectionDialog extends DialogComponentProvider {

	private PluginTool tool;
	private List<ScriptInfo> scriptInfos;
	private LinkedList<String> recentScripts;
	private String initialScript;
	private ScriptInfo userChoice;
	private SearchList<ScriptInfo> searchList;

	ScriptSelectionDialog(GhidraScriptMgrPlugin plugin, List<ScriptInfo> scriptInfos,
			LinkedList<String> recentScripts, String initialScript) {
		super("Run Script", true, true, true, false);
		this.tool = plugin.getTool();
		this.scriptInfos = scriptInfos;
		this.recentScripts = recentScripts;
		this.initialScript = initialScript;

		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();

		setHelpLocation(new HelpLocation(plugin.getName(), "Script Quick Launch"));
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());

		ScriptsModel model = new ScriptsModel(scriptInfos, recentScripts);
		searchList = new SearchList<>(model, (script, category) -> scriptChosen(script));
		searchList.setItemRenderer(new ScriptRenderer());
		searchList.setDisplayNameFunction((script, category) -> script.getName());

		// Pre-select the initial script if provided
		if (initialScript != null && !initialScript.isEmpty()) {
			Swing.runLater(() -> {
				for (ScriptInfo info : scriptInfos) {
					if (info.getName().equals(initialScript)) {
						searchList.setSelectedItem(info);
						break;
					}
				}
			});
		}

		panel.add(searchList, BorderLayout.CENTER);
		panel.setPreferredSize(new Dimension(600, 400));

		return panel;
	}

	private void scriptChosen(ScriptInfo script) {
		if (script != null) {
			userChoice = script;
			close();
		}
	}

	public void show() {
		tool.showDialog(this);
	}

	public ScriptInfo getUserChoice() {
		return userChoice;
	}

	@Override
	protected void dialogShown() {
		Swing.runLater(() -> searchList.getFilterField().requestFocus());
	}

	@Override
	protected void cancelCallback() {
		userChoice = null;
		super.cancelCallback();
	}

	@Override
	protected void okCallback() {
		ScriptInfo selectedScript = searchList.getSelectedItem();

		if (selectedScript == null) {
			setStatusText("Please select a script");
			return;
		}

		userChoice = selectedScript;
		clearStatusText();
		close();
	}

//=================================================================================================
// Inner Classes
//=================================================================================================

	/**
	 * Custom renderer for script entries in the search list.
	 */
	private class ScriptRenderer extends GListCellRenderer<SearchListEntry<ScriptInfo>> {
		{
			setHTMLRenderingEnabled(true);
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends SearchListEntry<ScriptInfo>> list,
				SearchListEntry<ScriptInfo> entry, int index, boolean isSelected, boolean cellHasFocus) {

			super.getListCellRendererComponent(list, entry, index, isSelected, cellHasFocus);

			if (entry == null) {
				return this;
			}

			ScriptInfo script = entry.value();

			// Build display text
			StringBuilder html = new StringBuilder("<html>");

			// Script name
			html.append("<b>").append(HTMLUtilities.escapeHTML(script.getName())).append("</b>");

			// Keybinding if available
			KeyStroke keyBinding = script.getKeyBinding();
			if (keyBinding != null) {
				html.append(" <font color=\"")
				    .append(Palette.GRAY.toHexString())
				    .append("\"><i>(")
				    .append(keyBinding.toString())
				    .append(")</i></font>");
			}

			// Description on next line
			String description = script.getDescription();
			if (description != null && !description.isEmpty()) {
				html.append("<br><font color=\"")
				    .append(Palette.GRAY.toHexString())
				    .append("\">")
				    .append(HTMLUtilities.escapeHTML(truncateDescription(description)))
				    .append("</font>");
			}

			html.append("</html>");

			setText(html.toString());
			setIcon(script.getToolBarImage(false));

			return this;
		}

		private String truncateDescription(String description) {
			// Remove newlines and limit length for display
			String clean = description.replaceAll("\\s+", " ").trim();
			if (clean.length() > 100) {
				return clean.substring(0, 97) + "...";
			}
			return clean;
		}
	}
}
