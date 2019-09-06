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
package ghidra.framework.plugintool.dialog;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import javax.swing.event.*;

import docking.DialogComponentProvider;
import docking.options.editor.ButtonPanelFactory;
import docking.util.image.ToolIconURL;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.label.GLabel;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.project.tool.GhidraToolTemplate;
import ghidra.util.HelpLocation;
import ghidra.util.NamingUtilities;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.layout.PairLayout;
import resources.ResourceManager;

/**
 * Shows the modal dialog to save tool configuration to the current
 * name or to a new name.
 */
public class SaveToolConfigDialog extends DialogComponentProvider implements ListSelectionListener {

	/**
	 * Preference name for images directory that was last accessed.
	 */
	final static String LAST_ICON_DIRECTORY = "LastIconDirectory";

	private ToolServices toolServices;
	private PluginTool tool;
	private ToolChest toolChest;
	private String defaultName;
	private ToolIconURL iconURL;
	private boolean selectionChanging;

	private JTextField nameField;
	private JList<ToolIconURL> iconList;
	private DefaultListModel<ToolIconURL> iconListModel;
	private JTextField iconField;
	private JButton browseButton;
	private JButton saveButton;
	private boolean didCancel;

	public SaveToolConfigDialog(PluginTool tool, ToolServices toolServices) {
		super("Save Tool to Tool Chest", true);
		this.tool = tool;
		this.toolServices = toolServices;

		addWorkPanel(buildMainPanel());

		saveButton = new JButton("Save");
		saveButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ev) {
				save();
			}
		});
		addButton(saveButton);
		addCancelButton();

		toolChest = toolServices.getToolChest();
		addListeners();
		setHelpLocation(new HelpLocation("FrontEndPlugin", "Save Tool"));
	}

	/**
	 * Define the Main panel for the dialog here.
	 * @return JPanel the completed Main Panel
	 */
	protected JPanel buildMainPanel() {
		JPanel iconPanel = createIconPanel();
		JPanel iconFieldPanel = createIconFieldPanel();
		addIconPanelListeners();

		JPanel toolFieldPanel = createToolFieldPanel();

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(toolFieldPanel, BorderLayout.NORTH);
		panel.add(iconPanel, BorderLayout.CENTER);
		panel.add(iconFieldPanel, BorderLayout.SOUTH);
		panel.setPreferredSize(new Dimension(400, 300));
		return panel;
	}

	/**
	 * Display the "Save Tool Configuration As..." dialog;
	 * blocks until user hits the "Cancel" button.
	 * 
	 * @param name original name for the tool
	 */
	public void show(String name, String newDefaultName) {
		this.defaultName = newDefaultName;
		didCancel = false;

		iconListModel.removeAllElements();
		loadIcons();

		ToolTemplate[] template = toolChest.getToolTemplates();

		for (ToolTemplate element : template) {
			ToolIconURL iconUrl = ((GhidraToolTemplate) element).getIconURL();
			updateMap(iconUrl);
		}

		nameField.setText(newDefaultName);
		setFocusComponent(nameField);
		nameField.selectAll();

		ToolIconURL iconUrl = tool.getIconURL();
		Icon icon = iconUrl.getIcon();
		String iconName = null;
		if (icon != null) {
			String location = iconUrl.getLocation();
			File file = new File(location);
			if (file.exists()) {
				iconName = location;
			}
			else {
				iconName = ResourceManager.getIconName(icon);
			}

			iconField.setText(iconName);
			updateMap(iconUrl);
		}

		loadIcons();
		if (iconName != null) {
			iconList.setSelectedValue(iconUrl, true);
		}

		tool.showDialog(this);
	}

	/**
	 * Listener for the icon list.
	 */
	@Override
	public void valueChanged(ListSelectionEvent e) {
		if (e.getValueIsAdjusting()) {
			return;
		}

		JList theList = (JList) e.getSource();
		if (theList.isSelectionEmpty()) {
			saveButton.setEnabled(false);
		}
		else {
			int index = theList.getSelectedIndex();
			ToolIconURL url = iconListModel.get(index);
			selectionChanging = true;
			iconField.setText(url.getLocation());
			selectionChanging = false;
			setPicture(url);
		}
	}

	/////////////////////////////////////////////////////
	/// *** private methods
	////////////////////////////////////////////////////

	private void addListeners() {

		nameField.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				save();
			}
		});
		nameField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				clearStatusText();
			}
		});
	}

	/**
	 * Calls a method in ToolManager to save the tool configuration to a
	 * different name.
	 */
	private void save() {

		String newName = nameField.getText().trim();

		if (newName.length() == 0) {
			this.setStatusText("Please enter or select a name.");
			return;
		}

		if (newName.indexOf(" ") >= 0) {
			setStatusText("Name cannot have spaces.");
			nameField.requestFocus();
			return;
		}
		if (!NamingUtilities.isValidName(newName)) {
			setStatusText("Invalid character in name: " + NamingUtilities.findInvalidChar(newName));
			nameField.requestFocus();
			return;
		}

		if (newName.equals(defaultName)) {
			saveToolConfig();
		}
		else if (isOverwriteExistingTool(newName)) {
			if (OptionDialog.showOptionDialog(tool.getToolFrame(), "Overwrite Tool?",
				"Overwrite existing tool, " + newName + "?", "Overwrite",
				OptionDialog.QUESTION_MESSAGE) == OptionDialog.OPTION_ONE) {
				tool.setToolName(newName);
				saveToolConfig();
			}
			else {
				return;
			}
		}
		else {
			tool.setToolName(newName);
			saveToolConfig();
		}
		close();
	}

	private boolean isOverwriteExistingTool(String newName) {
		ToolTemplate[] templates = toolChest.getToolTemplates();
		for (ToolTemplate template : templates) {
			if (template.getName().equals(newName)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Invoked when the 'Cancel' button is clicked
	 */
	@Override
	protected void cancelCallback() {
		didCancel = true;
		close();
	}

	public boolean didCancel() {
		return didCancel;
	}

	/**
	 * Create a panel that has text fields for entering a 
	 * name and tool description
	 */
	private JPanel createToolFieldPanel() {

		JPanel namePanel = new JPanel(new PairLayout(5, 5, 150));
		Border border = BorderFactory.createEmptyBorder(5, 3, 3, 3);
		namePanel.setBorder(border);

		nameField = new JTextField(11);
		nameField.setName("ToolName");

		namePanel.add(new GLabel("Tool Name:", SwingConstants.RIGHT));
		namePanel.add(nameField);

		return namePanel;
	}

	private JPanel createIconPanel() {
		iconListModel = new DefaultListModel<>();
		loadIcons();

		iconList = new JList<>(iconListModel);
		iconList.setLayoutOrientation(JList.HORIZONTAL_WRAP);
		iconList.setName("IconList");
		iconList.setCellRenderer(new ToolIconUrlRenderer());
		iconList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		iconList.setSelectedIndex(0);
		iconList.setVisibleRowCount(2);
		iconList.addListSelectionListener(this);

		JScrollPane iconListScrollPane = new JScrollPane(iconList);

		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(new TitledBorder("Choose Icon"));
		panel.add(iconListScrollPane, BorderLayout.CENTER);
		return panel;
	}

	private JPanel createIconFieldPanel() {
		iconField = new JTextField(12);
		iconField.setName("IconName");

		browseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);

		JPanel panel = new JPanel(new BorderLayout(5, 0));
		panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		panel.add(new GLabel("Icon Name:"), BorderLayout.WEST);
		panel.add(iconField, BorderLayout.CENTER);
		panel.add(browseButton, BorderLayout.EAST);
		return panel;
	}

	/**
	 * Add listeners for components in the icon panel.
	 */
	private void addIconPanelListeners() {

		iconField.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String filename = iconField.getText();
				if (filename.length() == 0) {
					setStatusText("Please enter a filename for the icon.");
					return;
				}
				setPicture(new ToolIconURL(filename));
			}
		});

		iconField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				clearStatusText();
			}
		});
		DocumentListener dl = new DocumentListener() {
			/* (non Javadoc)
			 * @see javax.swing.event.DocumentListener#changedUpdate(javax.swing.event.DocumentEvent)
			 */
			@Override
			public void changedUpdate(DocumentEvent e) {
				lookupIconName();
			}

			/* (non Javadoc)
			 * @see javax.swing.event.DocumentListener#removeUpdate(javax.swing.event.DocumentEvent)
			 */
			@Override
			public void removeUpdate(DocumentEvent e) {
				lookupIconName();
			}

			/* (non Javadoc)
			 * @see javax.swing.event.DocumentListener#insertUpdate(javax.swing.event.DocumentEvent)
			 */
			@Override
			public void insertUpdate(DocumentEvent e) {
				lookupIconName();
			}
		};
		iconField.getDocument().addDocumentListener(dl);

		browseButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				browseForIcons();
			}
		});

	}

	private void lookupIconName() {
		if (selectionChanging) {
			return;
		}

		String str = iconField.getText();

		for (int i = 0; i < iconListModel.getSize(); ++i) {
			ToolIconURL url = iconListModel.get(i);
			if (url.getLocation().equals(str)) {
				Rectangle r = iconList.getCellBounds(i, i);
				iconList.scrollRectToVisible(r);
				break;
			}
		}
	}

	/**
	 * Pop up a file chooser for the user to look for icon images.
	 */
	private void browseForIcons() {
		GhidraFileChooser iconFileChooser = new GhidraFileChooser(getComponent());
		iconFileChooser.setFileSelectionMode(GhidraFileChooser.FILES_ONLY);
		iconFileChooser.setTitle("Choose Icon");
		iconFileChooser.setApproveButtonToolTipText("Choose Icon");
		iconFileChooser.setFileFilter(
			new ExtensionFileFilter(new String[] { "gif", "jpg", "bmp", "png" }, "Image Files"));
		String iconDir = Preferences.getProperty(LAST_ICON_DIRECTORY);
		if (iconDir != null) {
			iconFileChooser.setCurrentDirectory(new File(iconDir));
		}
		File file = iconFileChooser.getSelectedFile();
		if (file == null) {
			return;
		}

		String filename = file.getAbsolutePath();
		iconField.setText(filename);

		ToolIconURL url = new ToolIconURL(filename);
		iconListModel.addElement(url);
		iconList.setSelectedValue(url, true);
		setPicture(url);

		Preferences.setProperty(LAST_ICON_DIRECTORY, file.getParent());
	}

	/**
	 * Set the picture with the icon.
	 */
	private void setPicture(ToolIconURL url) {

		boolean isAnimated = url.isAnimated();

		if (isAnimated) {
			setStatusText("Animated Icon not permitted.");
			saveButton.setEnabled(false);
		}
		else {
			clearStatusText();
			saveButton.setEnabled(true);
		}

		iconURL = url;
	}

	/**
	 * Set the icon and the description on the tool and call the method
	 * in ToolServices to save the tool.
	 */
	private void saveToolConfig() {
		if (iconURL == null) {
			String iconName = iconField.getText();
			if (iconName.length() > 0) {
				iconURL = new ToolIconURL(iconName);
			}
		}
		if (iconURL != null) {
			tool.setIconURL(iconURL);
			IconMap.put(iconURL.getLocation(), iconURL);
		}
		toolServices.saveTool(tool);
	}

	/**
	 * Get the icons from the icon map.
	 */
	private void loadIcons() {
		iconListModel.removeAllElements();
		List<ToolIconURL> urls = IconMap.getIcons();
		for (ToolIconURL url : urls) {
			iconListModel.addElement(url);
		}
	}

	/**
	 * Update the icon map and the list model for the icon name.
	 */
	private void updateMap(ToolIconURL url) {
		if (!iconListModel.contains(url)) {

			IconMap.put(url.getLocation(), url);

			loadIcons();
		}
	}

}
