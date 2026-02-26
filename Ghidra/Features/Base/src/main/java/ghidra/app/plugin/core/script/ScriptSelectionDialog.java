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
import java.util.function.BiPredicate;
import java.util.regex.Pattern;

import javax.swing.*;
import javax.swing.event.ListDataEvent;
import javax.swing.event.ListDataListener;
import javax.swing.text.html.HTMLEditorKit;

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
import ghidra.util.UserSearchUtils;

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
	private JTextPane detailPane;

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
		ScriptsModel model = new ScriptsModel(scriptInfos, recentScripts);
		searchList = new SearchList<ScriptInfo>(model, (script, category) -> scriptChosen(script)) {
			@Override
			protected BiPredicate<ScriptInfo, String> createFilter(String text) {
				Pattern pattern = UserSearchUtils.createContainsPattern(text, true, Pattern.CASE_INSENSITIVE);
				return (script, category) -> pattern.matcher(script.getName()).matches();
			}
		};
		searchList.setItemRenderer(new ScriptRenderer());
		searchList.setDisplayNameFunction((script, category) -> script.getName());

		// Add selection listener to update detail pane
		searchList.setSelectionCallback(this::updateDetailPane);

		// Add model listener to reset selection when filter changes
		model.addListDataListener(new ListDataListener() {
			@Override
			public void intervalAdded(ListDataEvent e) {
				resetSelectionToFirst();
			}

			@Override
			public void intervalRemoved(ListDataEvent e) {
				resetSelectionToFirst();
			}

			@Override
			public void contentsChanged(ListDataEvent e) {
				resetSelectionToFirst();
			}
		});

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

		JComponent detailPaneComponent = buildDetailPane();

		// Create split pane with list on left, detail on right
		JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		splitPane.setLeftComponent(searchList);
		splitPane.setRightComponent(detailPaneComponent);
		splitPane.setResizeWeight(0.67);  // 2/3 for list, 1/3 for detail pane
		splitPane.setDividerLocation(533);  // Initial divider: 2/3 of 800px

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(splitPane, BorderLayout.CENTER);
		panel.setPreferredSize(new Dimension(800, 500));

		return panel;
	}

	private JComponent buildDetailPane() {
		detailPane = new JTextPane();
		detailPane.setEditable(false);
		detailPane.setEditorKit(new HTMLEditorKit());
		detailPane.setName("Script Details");

		JScrollPane scrollPane = new JScrollPane(detailPane);
		// Adjust scroll increments for better HTML rendering
		scrollPane.getVerticalScrollBar().setUnitIncrement(5);
		scrollPane.getHorizontalScrollBar().setUnitIncrement(5);

		return scrollPane;
	}

	private void updateDetailPane(ScriptInfo script) {
		String text = (script != null) ? script.getToolTipText() : "";
		SwingUtilities.invokeLater(() -> {
			detailPane.setText(text);
			detailPane.setCaretPosition(0);
		});
	}

	private void resetSelectionToFirst() {
		SwingUtilities.invokeLater(() -> {
			ScriptsModel model = (ScriptsModel) searchList.getModel();
			if (model.getSize() > 0) {
				ScriptInfo firstScript = model.getElementAt(0).value();
				searchList.setSelectedItem(firstScript);
			}
		});
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

			StringBuilder html = new StringBuilder("<html>");
			html.append("<b>").append(HTMLUtilities.escapeHTML(script.getName())).append("</b>");

			KeyStroke keyBinding = script.getKeyBinding();
			if (keyBinding != null) {
				html.append(" <font color=\"")
				    .append(Palette.GRAY.toHexString())
				    .append("\"><i>(")
				    .append(keyBinding.toString())
				    .append(")</i></font>");
			}

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
			// Remove newlines and normalize whitespace
			String clean = description.replaceAll("\\s+", " ").trim();

			// Allow up to ~120 characters total (roughly 2 lines at ~60 chars per line)
			int maxLength = 120;
			if (clean.length() > maxLength) {
				return clean.substring(0, maxLength - 3) + "...";
			}
			return clean;
		}
	}
}
