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
package docking.options.editor;

import java.awt.*;
import java.beans.PropertyChangeListener;
import java.beans.PropertyEditor;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;
import java.util.regex.Pattern;

import javax.swing.*;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import docking.help.Help;
import docking.help.HelpService;
import docking.widgets.MultiLineLabel;
import docking.widgets.OptionDialog;
import docking.widgets.label.GIconLabel;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.internal.DefaultGTreeDataTransformer;
import ghidra.framework.options.*;
import ghidra.util.*;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.layout.MiddleLayout;
import ghidra.util.task.SwingUpdateManager;
import resources.ResourceManager;

public class OptionsPanel extends JPanel {
	private PropertyChangeListener changeListener;

	private GTree gTree;
	private OptionsRootTreeNode rootNode;

	private OptionsEditor currentOptionsEditor;
	private Map<OptionsTreeNode, OptionsEditor> editorMap = new HashMap<>();
	private JPanel viewPanel;
	private JPanel defaultPanel;
	private JPanel optionsEditorContainer;
	private JPanel restoreDefaultPanel;
	private SwingUpdateManager updateManager;
	private EditorStateFactory editorStateFactory = new EditorStateFactory();

	private JSplitPane splitPane;

	public OptionsPanel(String rootName, Options[] options, boolean showRestoreDefaultsButton,
			PropertyChangeListener changeListener) {
		this.changeListener = changeListener;

		updateManager = new SwingUpdateManager(100, () -> {
			OptionsTreeNode node = null;
			TreePath selectedPath = gTree.getSelectionPath();

			if (selectedPath != null) {
				node = (OptionsTreeNode) selectedPath.getLastPathComponent();
			}

			if (node == null) {
				return; // this can happen while the tree is loading and being filtered
			}

			processSelection(node);
		});

		setLayout(new BorderLayout());

		// assume that one options implies it's a root
		if (options.length == 1) {
			rootNode = new OptionsRootTreeNode(options[0]);
		}
		// else, create a dummy root with the given name
		else {
			rootNode = new OptionsRootTreeNode(rootName, options);
		}

		gTree = new GTree(rootNode);

		gTree.addGTreeSelectionListener(e -> updateManager.updateLater());

		gTree.setDataTransformer(new OptionsDataTransformer());

		viewPanel = new JPanel(new BorderLayout());
		viewPanel.setName("View");

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, gTree, viewPanel);
		splitPane.setOneTouchExpandable(true);
		splitPane.setDividerLocation(250);

		Dimension minSize = new Dimension(100, 300);
		gTree.setMinimumSize(minSize);
		viewPanel.setMinimumSize(minSize);

		splitPane.setBorder(null);
		add(splitPane, BorderLayout.CENTER);

		gTree.expandPath(new TreePath(new Object[] { rootNode }));
		TreeSelectionModel selModel = gTree.getSelectionModel();
		selModel.setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		defaultPanel = createDefaultPanel();
		viewPanel.add(defaultPanel, BorderLayout.CENTER);
		gTree.setSelectedNode(rootNode);

		optionsEditorContainer = new JPanel(new BorderLayout());

		// put the component on the lower-right of the overall options pane
		restoreDefaultPanel = new JPanel();
		restoreDefaultPanel.setLayout(new BorderLayout());

		if (showRestoreDefaultsButton) {
			restoreDefaultPanel.add(createRestoreDefaultsButton(), BorderLayout.EAST);
		}
	}

	public void dispose() {
		updateManager.dispose();
		gTree.dispose();
	}

	private Component createRestoreDefaultsButton() {

		JButton button = new JButton("Restore Defaults");
		button.addActionListener(e -> {
			Options currentOptions = getSelectedOptions();

			int userChoice = OptionDialog.showOptionDialog(viewPanel, "Restore Defaults?",
				"<html>Restore <b>" + HTMLUtilities.escapeHTML(currentOptions.getName()) +
					"</b> to default option values <b>and erase current settings?</b>",
				"Restore Defaults");
			if (userChoice == OptionDialog.CANCEL_OPTION) {
				return;
			}

			restoreDefaultOptionsForCurrentEditor();
		});
		return button;
	}

	Component getFocusComponent() {
		return gTree.getFilterField();
	}

	private void restoreDefaultOptionsForCurrentEditor() {
		TreePath selectedPath = gTree.getSelectionPath();
		if (selectedPath == null) {
			// shouldn't happen, as we are called by a button that only exists when selected path
			return;
		}

		OptionsTreeNode node = (OptionsTreeNode) selectedPath.getLastPathComponent();
		if (node == null) {
			// don't know how this can happen
			return;
		}
		Options options = node.getOptions();
		options.restoreDefaultValues();
		OptionsEditor optionsEditor = options.getOptionsEditor();
		if (optionsEditor != null) {
			optionsEditor.reload();
		}

		editorMap.remove(node);
		List<String> optionNames = node.getOptionNames();
		for (String optionName : optionNames) {
			editorStateFactory.clear(options, optionName);
		}

		processSelection(node);
	}

	public boolean cancel() {
		Set<Entry<OptionsTreeNode, OptionsEditor>> entrySet = editorMap.entrySet();
		for (Map.Entry<OptionsTreeNode, OptionsEditor> entry : entrySet) {
			OptionsEditor editor = entry.getValue();
			try {
				editor.cancel();
			}
			catch (Exception e) {
				String msg = e.getMessage();
				if (msg == null) {
					msg = e.toString();
				}
				String title = "Error Resetting Options on " + entry.getKey().getName();
				Msg.showError(this, this, title, title + "\nError Message: " + msg, e);
			}
		}

		return true;
	}

	public boolean apply() {
		boolean status = true;
		Set<Entry<OptionsTreeNode, OptionsEditor>> entrySet = editorMap.entrySet();
		for (Map.Entry<OptionsTreeNode, OptionsEditor> entry : entrySet) {
			OptionsEditor editor = entry.getValue();
			try {
				editor.apply();
			}
			catch (OptionsVetoException ove) {
				Msg.showWarn(this, this, "Invalid Option Value",
					"Attempted to set an option to an invalid value:\n" + ove.getMessage());
			}
			catch (Exception e) {
				status = false;
				String msg = e.getMessage();
				if (msg == null) {
					msg = e.toString();
				}
				String title = "Error Setting Options on " + entry.getKey().getName();
				Msg.showError(this, this, title, title + "\nError Message: " + msg, e);
			}
		}

		return status;
	}

	public void displayCategory(String category, String filterText) {
		String escapedDelimiter = Pattern.quote(Options.DELIMITER_STRING);

		GTreeNode root = gTree.getModelRoot();
		category = root.getName() + Options.DELIMITER_STRING + category;
		String[] categories = category.split(escapedDelimiter);
		gTree.setFilterText(filterText);
		gTree.setSelectedNodeByNamePath(categories);
	}

	private JPanel createDefaultPanel() {
		JPanel panel = new JPanel(new MiddleLayout());
		panel.setName("Default");

		MultiLineLabel label =
			new MultiLineLabel("To change Options, select a Folder or Option Group from the\n" +
				"Options Tree and change the Option settings.");
		label.setName("DefaultInfo");

		JPanel labelPanel = new JPanel();
		labelPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 0));
		BoxLayout bl = new BoxLayout(labelPanel, BoxLayout.X_AXIS);
		labelPanel.setLayout(bl);
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(new GIconLabel(ResourceManager.loadImage("images/information.png")));
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(label);

		panel.add(labelPanel);
		return panel;
	}

	private void processSelection(OptionsTreeNode selectedNode) {

		if (selectedNode == null) {
			setViewPanel(defaultPanel, selectedNode);
			return;
		}

		currentOptionsEditor = getOptionsEditor(selectedNode);
		if (currentOptionsEditor == null) {
			setViewPanel(defaultPanel, selectedNode);
			return;
		}

		JComponent editorComponent =
			currentOptionsEditor.getEditorComponent(selectedNode.getOptions(), editorStateFactory);
		if (editorComponent == null) {
			setViewPanel(defaultPanel, selectedNode);
			return;
		}

		editorComponent.setRequestFocusEnabled(true); // TODO: do we really need this?
		optionsEditorContainer.removeAll();
		optionsEditorContainer.add(editorComponent, BorderLayout.CENTER);

		optionsEditorContainer.add(restoreDefaultPanel, BorderLayout.SOUTH);

		setViewPanel(optionsEditorContainer, selectedNode);
	}

	private Options getSelectedOptions() {
		TreePath selectedPath = gTree.getSelectionPath();
		if (selectedPath == null) {
			// shouldn't happen, as we are called by a button that only exists when selected path
			return null;
		}

		OptionsTreeNode node = (OptionsTreeNode) selectedPath.getLastPathComponent();
		if (node == null) {
			// don't know how this can happen
			return null;
		}
		return node.getOptions();
	}

	private void setViewPanel(JComponent component, OptionsTreeNode selectedNode) {
		viewPanel.removeAll();
		viewPanel.add(component, BorderLayout.CENTER);
		setHelpLocation(component, selectedNode);
		viewPanel.validate();
		viewPanel.repaint();
	}

	private void setHelpLocation(JComponent component, OptionsTreeNode node) {

		Options options = node.getOptions();
		if (options == null) {
			return; // not sure this can happen
		}

		HelpService help = Help.getHelpService();
		HelpLocation location = options.getOptionsHelpLocation();
		if (location == null) {
			// The tree node may or may not have help.  The leaf options should all have help.
			help.clearHelp(this);
		}
		else {
			help.registerHelp(this, location);
		}
	}

	private OptionsEditor getOptionsEditor(OptionsTreeNode node) {
		OptionsEditor editor = editorMap.get(node);
		if (editor != null) {
			return editor;
		}

		Options options = node.getOptions();
		if (options == null) {
			return null;
		}
		List<String> optionList = node.getOptionNames();

		editor = options.getOptionsEditor();
		if (editor == null) {
			if (optionList.size() > 0) {
				editor = new ScrollableOptionsEditor(options.getName(), options, optionList,
					editorStateFactory);
			}
		}

		if (editor != null) {
			editorMap.put(node, editor);
			editor.setOptionsPropertyChangeListener(changeListener);
		}

		return editor;
	}

	void setSelectedPath(TreePath path) {
		if (path == null) {
			return;
		}

		gTree.expandPath(path);
		gTree.setSelectionPath(path);
	}

	TreePath getSelectedPath() {
		return gTree.getSelectionPath();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	public class OptionsDataTransformer extends DefaultGTreeDataTransformer {
		@Override
		public List<String> transform(GTreeNode node) {
			List<String> results = super.transform(node);

			//add in options details
			OptionsTreeNode optionsNode = (OptionsTreeNode) node;
			Options options = optionsNode.getOptions();
			List<String> optionsList = optionsNode.getOptionNames();
			for (String optionName : optionsList) {
				addDetails(options, optionName, results);
			}
			return results;
		}

		private void addDetails(Options options, String optionName, List<String> results) {
			// some options use property editor classes to handle options editing and not 
			// EditableOptions objects directly
			PropertyEditor propertyEditor = options.getRegisteredPropertyEditor(optionName);
			if (propertyEditor instanceof CustomOptionsEditor) {
				addOptionDetails((CustomOptionsEditor) propertyEditor, results);
			}
			else {
				String description = options.getDescription(optionName);
				results.add(optionName);
				results.add(description);
			}
		}

		private void addOptionDetails(CustomOptionsEditor editor, List<String> results) {
			String[] optionNames = editor.getOptionNames();
			for (String string : optionNames) {
				results.add(string);
			}

			String[] descriptions = editor.getOptionDescriptions();
			for (String string : descriptions) {
				results.add(string);
			}
		}
	}

}
