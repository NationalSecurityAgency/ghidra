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
package ghidra.framework.main;

import java.awt.*;
import java.awt.event.*;
import java.util.HashSet;
import java.util.Set;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.*;
import docking.event.mouse.GMouseListenerAdapter;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.widgets.tree.support.GTreeSelectionEvent;
import docking.widgets.tree.support.GTreeSelectionListener;
import ghidra.framework.main.datatree.DialogProjectTreeContext;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.main.projectdata.actions.*;
import ghidra.framework.model.*;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.PairLayout;

/**
 * Dialog to open or save domain data items to a new location or name.
 */
public class DataTreeDialog extends DialogComponentProvider
		implements GTreeSelectionListener, ActionListener {

	/**
	 * Dialog type for opening domain data files.
	 */
	public final static int OPEN = 0;
	/**
	 * Dialog type for saving domain data files.
	 */
	public final static int SAVE = 1;
	/**
	 * Dialog type for choosing a user folder.
	 */
	public final static int CHOOSE_FOLDER = 2;
	/**
	 * Dialog type for creating domain data files.
	 */
	public final static int CREATE = 3;

	protected final static int WIDTH = 350;
	protected final static int HEIGHT = 500;

	protected ProjectDataTreePanel treePanel;

	private JComboBox<String> projectComboBox; // used for open data
	private ProjectLocator[] projectLocators;
	private DomainFileFilter filter;
	private JTextField nameField;
	private JLabel folderNameLabel;
	private ActionListener okActionListener;
	private DomainFolder domainFolder;
	private DomainFile domainFile;
	private int type;
	private Component parent;

	private String searchString;
	private boolean cancelled = false;

	private ProjectDataExpandAction<DialogProjectTreeContext> expandAction;
	private ProjectDataCollapseAction<DialogProjectTreeContext> collapseAction;
	private ProjectDataNewFolderAction<DialogProjectTreeContext> newFolderAction;

	private Integer treeSelectionMode;
	private final Project project;

	/**
	 * Construct a new DataTreeDialog for the active project.  This chooser will show all project
	 * files.  Following linked-folders will only be allowed if a type of {@link #CHOOSE_FOLDER}
	 * or {@link #OPEN} is specified.  If different behavior is required a filter should 
	 * be specified using the other constructor. 
	 *
	 * @param parent dialog's parent
	 * @param title title to use
	 * @param type specify OPEN, SAVE, CHOOSE_FOLDER, CHOOSE_USER_FOLDER, or CREATE
	 * @throws IllegalArgumentException if invalid type is specified
	 */
	public DataTreeDialog(Component parent, String title, int type) {
		this(parent, title, type, getDefaultFilter(type), AppInfo.getActiveProject());
	}

	/**
	 * Construct a new DataTreeDialog for the active project.
	 *
	 * @param parent dialog's parent
	 * @param title title to use
	 * @param type specify OPEN, SAVE, CHOOSE_FOLDER, or CHOOSE_USER_FOLDER
	 * @param filter filter used to control what is displayed in the data tree
	 * @throws IllegalArgumentException if invalid type is specified
	 */
	public DataTreeDialog(Component parent, String title, int type, DomainFileFilter filter) {
		this(parent, title, type, filter, AppInfo.getActiveProject());
	}

	/**
	 * Construct a new DataTreeDialog for the given project.
	 *
	 * @param parent dialog's parent
	 * @param title title to use
	 * @param type specify OPEN, SAVE, CHOOSE_FOLDER, or CHOOSE_USER_FOLDER
	 * @param filter filter used to control what is displayed in the data tree
	 * @param project the project to browse
	 * @throws IllegalArgumentException if invalid type is specified
	 */
	public DataTreeDialog(Component parent, String title, int type, DomainFileFilter filter,
			Project project) {
		super(title, true, true, true, false);

		if (type < 0 || type > CREATE) {
			throw new IllegalArgumentException("Invalid type specified: " + type);
		}

		this.project = project;
		this.parent = parent;
		this.type = type;
		this.filter = filter;

		addWorkPanel(buildMainPanel());
		initializeButtons();
		rootPanel.setPreferredSize(new Dimension(WIDTH, HEIGHT));

		initializeFocusedComponent();

		createActions();
	}

	private void initializeFocusedComponent() {
		Component focusComponent = nameField;
		if (!nameField.isEditable()) {
			focusComponent = treePanel.getFilterField();
		}
		setFocusComponent(focusComponent);
	}

	public void setTreeSelectionMode(int mode) {
		if (treePanel != null) {
			treePanel.getTreeSelectionModel().setSelectionMode(mode);
		}
		treeSelectionMode = mode;
	}

	private void initializeButtons() {
		addOKButton();
		addCancelButton();

		if (type == SAVE) {
			okButton.setText("Save");
			okButton.setMnemonic('S');
		}
		else if (type == CREATE) {
			okButton.setText("Create");
			okButton.setMnemonic('C');
		}
		setOkEnabled(false);

	}

	private void createActions() {
		String owner = "DataTreeDialogActions";

		String groupName = "Cut/copy/paste/new";
		newFolderAction = new DialogProjectDataNewFolderAction(owner, groupName);

		groupName = "Expand/Collapse";
		expandAction = new DialogProjectDataExpandAction(owner, groupName);
		collapseAction = new DialogProjectDataCollapseAction(owner, groupName);

		addAction(newFolderAction);
		addAction(expandAction);
		addAction(collapseAction);
	}

	/**
	 * Add action listener that is called when the OK button is hit.
	 * @param l listener to add
	 */
	public void addOkActionListener(ActionListener l) {
		okActionListener = l;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (treePanel == null) {
			// must have been closed; some kind of timing issue
			return super.getActionContext(event);
		}
		return treePanel.getActionContext(null, event);
	}

	public void show() {
		DockingWindowManager.showDialog(parent, this);
	}

	/**
	 * Shows this dialog.  The preferred show method is {@link #show()}, as it is the preferred 
	 * nomenclature.
	 */
	public void showComponent() {
		show();
	}

	public String getNameText() {
		return nameField.getText();
	}

	public void setNameText(String name) {
		nameField.setText(name.trim());
		nameField.selectAll();
	}

	/**
	 * Sets a domain folder as the initially selected folder when the dialog is first shown.
	 *  
	 * @param folder {@link DomainFolder} to select when showing the dialog
	 */
	public void setSelectedFolder(DomainFolder folder) {
		if (folder != null) {
			treePanel.selectDomainFolder(folder);
		}
	}

	/**
	 * Get the selected domain file.
	 * @return null if there was no domain file selected
	 */
	public DomainFile getDomainFile() {

		if (domainFile != null) {
			return domainFile;
		}

		if (cancelled) {
			return null;
		}

		if (treePanel != null) {
			domainFile = treePanel.getSelectedDomainFile();
		}
		return domainFile;
	}

	/**
	 * Get the selected folder.
	 * @return null if there was no domain folder selected
	 */
	public DomainFolder getDomainFolder() {
		if (cancelled) {
			return null;
		}
		if (domainFolder == null) {
			domainFolder = treePanel.getSelectedDomainFolder();
		}
		return domainFolder;
	}

	/**
	 * TreeSelectionListener method that is called whenever the value of the selection changes.
	 * @param e the event that characterizes the change.
	 */
	@Override
	public void valueChanged(GTreeSelectionEvent e) {
		clearStatusText();

		if (type == CHOOSE_FOLDER) {
			domainFolder = treePanel.getSelectedDomainFolder();
			if (domainFolder != null) {
				DomainFolder folderParent = domainFolder.getParent();
				if (folderParent != null) {
					folderNameLabel.setText(folderParent.getPathname());
				}
				else {
					folderNameLabel.setText("    ");
				}

				nameField.setText(domainFolder.getName());
			}
			else {
				domainFile = treePanel.getSelectedDomainFile();
				if (domainFile != null) {
					domainFolder = domainFile.getParent();
					DomainFolder grandParent = domainFolder.getParent();
					if (grandParent != null) {
						folderNameLabel.setText(grandParent.getPathname());
					}
					else {
						folderNameLabel.setText("");
					}

					nameField.setText(domainFolder.getName());
				}
				else {
					domainFolder = project.getProjectData().getRootFolder();
					folderNameLabel.setText(domainFolder.getPathname());
					nameField.setText(domainFolder.getName());
				}
			}
		}
		else {
			domainFile = treePanel.getSelectedDomainFile();
			if (domainFile != null) {
				folderNameLabel.setText(domainFile.getParent().getPathname());
				nameField.setText(domainFile.getName());
				domainFolder = domainFile.getParent();
			}
			else {
				domainFolder = treePanel.getSelectedDomainFolder();
				if (domainFolder == null) {
					domainFolder = project.getProjectData().getRootFolder();
				}

				folderNameLabel.setText(domainFolder.getPathname());
				if (nameField.isEditable()) {
					if (nameField.getText().length() > 0) {
						nameField.selectAll();
					}
				}
				else {
					nameField.setText("");
				}
			}
		}

		String text = nameField.getText();
		setOkEnabled((text != null) && !text.isEmpty());
	}

	@Override
	public void actionPerformed(ActionEvent event) {
		int index = projectComboBox.getSelectedIndex();
		if (index < 0) {
			return;
		}

		ProjectLocator projectLocator = projectLocators[index];
		ProjectData pd = project.getProjectData(projectLocator);
		String projectName = projectLocator.getName();
		if (pd == null) {
			Msg.showError(this, getComponent(), "Error Getting Project Data",
				"Could not get project data for " + projectName);
		}
		else {
			treePanel.setProjectData(projectName, pd);
		}
	}

	/**
	 * Select the root folder in the tree.
	 */
	public void selectRootDataFolder() {
		Swing.runLater(() -> treePanel.selectRootDataFolder());
	}

	/**
	 * Select a folder in the tree.
	 * @param folder the folder to select
	 */
	public void selectFolder(DomainFolder folder) {
		Swing.runLater(() -> treePanel.selectDomainFolder(folder));
	}

	/**
	 * Select the node that corresponds to the given domain file.
	 * @param file the file
	 */
	public void selectDomainFile(DomainFile file) {
		Swing.runLater(() -> treePanel.selectDomainFile(file));
	}

	@Override
	public void close() {
		super.close();
		removeWorkPanel();
		if (treePanel != null) {
			treePanel.dispose();
		}
		treePanel = null;
	}

	protected JPanel buildMainPanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());

		JPanel namePanel = createNamePanel();

		// data tree panel must be created before the combo box
		JPanel dataTreePanel = createDataTreePanel();
		ProjectData pd = project.getProjectData();
		treePanel.setProjectData(project.getName(), pd);
		treePanel.selectRootDataFolder();

		if (type == OPEN) {
			JPanel comboPanel = createComboBoxPanel();

			panel.add(comboPanel, BorderLayout.NORTH);
			populateProjectModel();
		}

		panel.add(dataTreePanel, BorderLayout.CENTER);
		panel.add(namePanel, BorderLayout.SOUTH);

		// can't add tree listeners until everything is built
		addTreeListeners();
		return panel;
	}

	@Override
	protected void okCallback() {
		cancelled = false;

		if (okActionListener == null) {
			close();
			return;
		}
		okActionListener.actionPerformed(new ActionEvent(okButton, 0, okButton.getActionCommand()));
	}

	public boolean wasCancelled() {
		return cancelled;
	}

	@Override
	protected void cancelCallback() {
		cancelled = true;
		close();
	}

	/**
	 * Create the data tree panel.
	 */
	private JPanel createDataTreePanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		ProjectData pd = project.getProjectData();

		treePanel = new ProjectDataTreePanel(project.getName(), true, // is for the active project
			null, filter);
		if (treeSelectionMode != null) {
			treePanel.getTreeSelectionModel().setSelectionMode(treeSelectionMode);
		}
		treePanel.setProjectData(project.getName(), pd);
		treePanel.addTreeSelectionListener(this);
		treePanel.setPreferredTreePanelSize(new Dimension(150, 150));

		// don't put the filter in the dialog when the user can/must type a name, as it's confusing
		boolean userChoosesName = (type == SAVE) || (type == CREATE);
		treePanel.setTreeFilterEnabled(!userChoosesName);

		panel.add(treePanel, BorderLayout.CENTER);
		return panel;
	}

	protected void addTreeListeners() {
		if (type == OPEN) {

			treePanel.addTreeMouseListener(new GMouseListenerAdapter() {
				@Override
				public void doubleClickTriggered(MouseEvent e) {
					if (okButton.isEnabled()) {
						okCallback();
					}
				}
			});
		}
	}

	/**
	 * Create the combo box panel that shows list of project names that
	 * are currently open, including the active project.
	 */
	private JPanel createComboBoxPanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		panel.setBorder(new TitledBorder("Current Projects"));
		projectComboBox = new GComboBox<>();
		DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
		projectComboBox.setModel(model);
		model.addElement("defaultProject");
		panel.add(projectComboBox, BorderLayout.CENTER);
		projectComboBox.addActionListener(this);

		return panel;
	}

	private JPanel createNamePanel() {

		JPanel outerPanel = new JPanel();
		outerPanel.setLayout(new BorderLayout(5, 0));

		nameField = new JTextField(12);
		nameField.getDocument().addDocumentListener(new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				update();
			}

			private void update() {
				String text = nameField.getText();

				switch (type) {
					case OPEN:
						// handled by valueChanged()
						break;
					case SAVE:
						if (text == null || text.isEmpty()) {
							DomainFile file = treePanel.getSelectedDomainFile();
							okButton.setEnabled(file != null);
						}
						break;
					case CREATE:
						if (text == null || text.isEmpty()) {
							DomainFile file = treePanel.getSelectedDomainFile();
							okButton.setEnabled(file != null);
						}
						break;
					case CHOOSE_FOLDER:
						// handled by valueChanged()
						break;
					default:
						throw new AssertException("Must handle new type!: " + type);
				}

				setOkEnabled((text != null) && !text.isEmpty());
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				update();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				update();
			}
		});

		boolean userChoosesName = (type == SAVE) || (type == CREATE);
		nameField.setEditable(userChoosesName);
		nameField.setEnabled(userChoosesName);

		JPanel namePanel = new JPanel(new PairLayout(2, 5, 100));

		if (!userChoosesName) {
			namePanel.setBorder(BorderFactory.createEmptyBorder(20, 5, 5, 5));
		}
		namePanel.add(new GLabel("Folder Path:", SwingConstants.RIGHT));

		folderNameLabel = new GDLabel("   ");
		namePanel.add(folderNameLabel);

		namePanel.add(
			new GLabel(type == CHOOSE_FOLDER ? "Folder Name:" : "Name:", SwingConstants.RIGHT));
		namePanel.add(nameField);

		outerPanel.add(namePanel, BorderLayout.CENTER);

		FieldKeyListener l = new FieldKeyListener();
		nameField.addKeyListener(l);
		nameField.addActionListener(e -> okCallback());

		return outerPanel;
	}

	private void populateProjectModel() {
		ProjectLocator[] views = project.getProjectViews();

		projectLocators = new ProjectLocator[views.length + 1];
		// make the current project the first in the list
		projectLocators[0] = project.getProjectLocator();
		for (int i = 0; i < views.length; i++) {
			projectLocators[i + 1] = views[i];
		}

		// populate the combo box
		DefaultComboBoxModel<String> model =
			(DefaultComboBoxModel<String>) projectComboBox.getModel();
		model.removeAllElements();

		Set<String> map = new HashSet<>();
		for (ProjectLocator projectLocator : projectLocators) {
			String name = projectLocator.getName();
			if (map.contains(name)) {
				model.addElement(name + " (" + projectLocator.getLocation() + ")");
			}
			else {
				map.add(name);
				model.addElement(name);
			}
		}
		map = null;
	}

	public void setSearchText(String s) {
		if (searchString != null) {
			treePanel.findAndSelect(s);
		}
	}

	private static DomainFileFilter getDefaultFilter(int type) {
		if (type == CHOOSE_FOLDER || type == OPEN) {
			// return filter which forces folder selection and allow navigation into linked-folders
			return new DomainFileFilter() {

				@Override
				public boolean accept(DomainFile df) {
					return true; // show all files (legacy behavior)
				}
			};
		}
		return null;
	}

	private class FieldKeyListener extends KeyAdapter {
		@Override
		public void keyPressed(KeyEvent e) {
			clearStatusText();
		}
	}

}
