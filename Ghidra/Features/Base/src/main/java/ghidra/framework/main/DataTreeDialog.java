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
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.main.projectdata.actions.*;
import ghidra.framework.model.*;
import ghidra.util.Msg;
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
	public final static int CHOOSE_FOLDER = 2; // choose only a
	// folder owned by the user
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
	private boolean comboModelInitialized;
	private boolean cancelled = false;
	private String pendingNameText;
	private DomainFolder pendingDomainFolder;

	private ProjectDataExpandAction expandAction;
	private ProjectDataCollapseAction collapseAction;
	private ProjectDataNewFolderAction newFolderAction;

	private Integer treeSelectionMode;

	/**
	 * Construct a new DataTreeDialog.
	 *
	 * @param parent dialog's parent
	 * @param title title to use
	 * @param type specify OPEN, SAVE, CHOOSE_FOLDER, CHOOSE_USER_FOLDER, or CREATE
	 * @throws IllegalArgumentException if invalid type is specified
	 */
	public DataTreeDialog(Component parent, String title, int type) {
		this(parent, title, type, null);
	}

	/**
	 * Construct a new DataTreeDialog.
	 *
	 * @param parent dialog's parent
	 * @param title title to use
	 * @param type specify OPEN, SAVE, CHOOSE_FOLDER, or CHOOSE_USER_FOLDER
	 * @param filter filter used to control what is displayed in the data tree
	 * @throws IllegalArgumentException if invalid type is specified
	 */
	public DataTreeDialog(Component parent, String title, int type, DomainFileFilter filter) {
		super(title, true, true, true, false);
		this.parent = parent;
		initDataTreeDialog(type, filter);
	}

	public void setTreeSelectionMode(int mode) {
		if (treePanel != null) {
			treePanel.getTreeSelectionModel().setSelectionMode(mode);
		}
		treeSelectionMode = mode;
	}

	private void initDataTreeDialog(int newType, DomainFileFilter newFilter) {

		if (newType < 0 || newType > CREATE) {
			throw new IllegalArgumentException("Invalid type specified: " + newType);
		}
		this.type = newType;
		this.filter = newFilter;

		okButton = new JButton("OK");
		okButton.setMnemonic('K');
		okButton.addActionListener(ev -> okCallback());
		addButton(okButton);
		addCancelButton();

		if (newType == SAVE) {
			okButton.setText("Save");
			okButton.setMnemonic('S');
		}

		if (newType == CREATE) {
			okButton.setText("Create");
			okButton.setMnemonic('C');
		}

		rootPanel.setPreferredSize(new Dimension(WIDTH, HEIGHT));

		setFocusComponent(nameField);

		createActions();
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

	public void showComponent() {
		doSetup();
		DockingWindowManager.showDialog(parent, this);
	}

	@Override
	protected void dialogShown() {
		if (!comboModelInitialized) {
			// make sure the combo box model has been populated
			doSetup();
		}
	}

	private void doSetup() {
		addWorkPanel(buildMainPanel());

		comboModelInitialized = true;
		// repopulate the tree
		Project project = AppInfo.getActiveProject();
		ProjectData pd = project.getProjectData();
		treePanel.setProjectData(project.getName(), pd);

		String nameFieldText = pendingNameText == null ? "" : pendingNameText;
		pendingNameText = null;
		initializeSelectedFolder();

		if (type == OPEN) {
			domainFolder = null;
			nameField.setText(nameFieldText);
			nameField.selectAll();
			populateProjectModel();
		}
		else if (type == SAVE) {
			nameField.setText(nameFieldText);
			nameField.selectAll();
			initializeSelectedFolder();
		}
		else if (type == CREATE) {
			nameField.setText(nameFieldText);
			nameField.selectAll();
			initializeSelectedFolder();
		}

		setOkEnabled(!nameFieldText.isEmpty());

		if (searchString != null) {
			findAndSelect(searchString);
		}

		clearStatusText();
	}

	private void initializeSelectedFolder() {
		if (pendingDomainFolder != null) {
			// set the explicitly requested folder to be selected
			treePanel.selectDomainFolder(pendingDomainFolder);
			pendingDomainFolder = null;
		}
		else {
			// default case--make sure we have a folder selected
			domainFolder = treePanel.getSelectedDomainFolder();
			if (domainFolder == null) {
				treePanel.selectRootDataFolder();
			}
		}
	}

	/**
	 * Get the name from the name field.
	 */
	public String getNameText() {
		return nameField.getText();
	}

	public void setNameText(String name) {
		pendingNameText = name;
	}

	public void setSelectedFolder(DomainFolder folder) {
		pendingDomainFolder = folder;
	}

	/**
	 * Get the selected domain file.
	 * @return null if there was no domain file selected
	 */
	public DomainFile getDomainFile() {
		if (domainFile == null && !cancelled) {
			domainFile = treePanel.getSelectedDomainFile();
		}
		return domainFile;
	}

	/**
	 * Get the selected folder.
	 * @return null if there was no domain folder selected
	 */
	public DomainFolder getDomainFolder() {
		if (domainFolder == null && !cancelled) {
			domainFolder = treePanel.getSelectedDomainFolder();
		}
		return domainFolder;
	}

	/**
	 * TreeSelectionListener method that is called whenever the value of the
	 * selection changes.
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
					domainFolder = AppInfo.getActiveProject().getProjectData().getRootFolder();
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
					domainFolder = AppInfo.getActiveProject().getProjectData().getRootFolder();
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

	/**
	 * Action listener for the project combo box.
	 * @param e event generated when a selection is made in the combo box
	 */
	@Override
	public void actionPerformed(ActionEvent e) {
		int index = projectComboBox.getSelectedIndex();
		if (index < 0) {
			return;
		}
		Project project = AppInfo.getActiveProject();
		try {
			ProjectData pd = project.getProjectData(projectLocators[index]);

			if (pd == null) {
				Msg.showError(getClass(), getComponent(), "Error Getting Project Data",
					"Could not get project data for " + projectLocators[index].getName());
			}
			else {
				treePanel.setProjectData(projectLocators[index].getName(), pd);
			}
		}
		catch (Exception exc) {
			Msg.showError(getClass(), getComponent(), "Error Getting Project Data", exc.toString(),
				exc);
		}
	}

	/**
	 * Select the root folder in the tree.
	 */
	public void selectRootDataFolder() {
		SwingUtilities.invokeLater(() -> treePanel.selectRootDataFolder());
	}

	/**
	 * Select the node that corresponds to the given domain file.
	 */
	public void selectDomainFile(final DomainFile file) {
		SwingUtilities.invokeLater(() -> treePanel.selectDomainFile(file));
	}

	/* (non-Javadoc)
	 * @see docking.DialogComponentProvider#close()
	 */
	@Override
	public void close() {
		super.close();
		removeWorkPanel();
		if (treePanel != null) {
			treePanel.dispose();
		}
		treePanel = null;
		comboModelInitialized = false;
	}

	/**
	 * Define the Main panel for the dialog here.
	 * @return JPanel the completed <CODE>Main Panel</CODE>
	 */
	protected JPanel buildMainPanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());

		// data tree panel must be created before the combo box
		JPanel dataTreePanel = createDataTreePanel();

		if (type == OPEN) {
			JPanel comboPanel = createComboBoxPanel();

			panel.add(comboPanel, BorderLayout.NORTH);
		}
		panel.add(dataTreePanel, BorderLayout.CENTER);

		JPanel namePanel = createNamePanel();
		panel.add(namePanel, BorderLayout.SOUTH);

		return panel;
	}

	/**
	 * Gets called when the user clicks on the OK Action for the dialog.
	 */
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

	/**
	 * Called when user hits the cancel button.
	 */
	@Override
	protected void cancelCallback() {
		cancelled = true;
		close();
	}

	/////////////////////////////////////////////////////////////////////

	/**
	 * Create the data tree panel.
	 */
	private JPanel createDataTreePanel() {

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		Project project = AppInfo.getActiveProject();
		ProjectData pd = project.getProjectData();

		treePanel = new ProjectDataTreePanel(project.getName(), true, // is for the active project
			null, filter);
		if (treeSelectionMode != null) {
			treePanel.getTreeSelectionModel().setSelectionMode(treeSelectionMode);
		}
		treePanel.setProjectData(project.getName(), pd);
		treePanel.addTreeSelectionListener(this);
		treePanel.setPreferredTreePanelSize(new Dimension(150, 150));

		addTreeListeners();

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

		// don't put the filter in the dialog when the user can/must type a name, as it's confusing
		treePanel.setTreeFilterEnabled(!userChoosesName);

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
		Project project = AppInfo.getActiveProject();
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

	public void findAndSelect(String s) {
		treePanel.findAndSelect(s);
	}

	public void setSearchText(String string) {
		searchString = string;
	}

	/////////////////////////////////////////////////////////////////////
	private class FieldKeyListener extends KeyAdapter {

		@Override
		public void keyPressed(KeyEvent e) {
			clearStatusText();
		}
	}

}
