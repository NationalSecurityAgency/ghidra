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
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.*;

import docking.options.editor.ButtonPanelFactory;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.list.GListCellRenderer;
import docking.widgets.table.GTable;
import docking.wizard.AbstractWizardJPanel;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.remote.User;
import ghidra.util.HelpLocation;
import resources.ResourceManager;
import util.CollectionUtils;

/**
 * Panel that shows the users for a given repository and the users associated with the current
 * shared project. There are 3 main sub-panels:
 * <p>
 * <ul>
 * <li>Known Users Panel: Displays all users in the repository</li>
 * <li>Button Panel: Provides buttons for adding/removing users from the project</li>
 * <li>User Access Panel: Displays all users on the project, and their access permissions</li>
 * </ul>
 * <p>
 * If the current user is an admin, he may change user permissions and add/remove them 
 * from the project. If not, only the User Access Panel will be visible and it will
 * be read-only.
 * 
 */
public class ProjectAccessPanel extends AbstractWizardJPanel {

	protected KnownUsersPanel knownUsersPanel;
	protected UserAccessPanel userAccessPanel;
	protected ButtonPanel addRemoveButtonPanel;
	protected JCheckBox anonymousAccessCB;

	protected String currentUser;
	protected List<User> origProjectUserList;
	protected boolean origAnonymousAccessEnabled;
	protected String repositoryName;
	protected HelpLocation helpLoc;

	protected final Color SELECTION_BG_COLOR = new Color(204, 204, 255);
	protected final Color SELECTION_FG_COLOR = Color.BLACK;

	protected PluginTool tool;

	/** 
	 * Construct a new panel from a {@link RepositoryAdapter} instance.
	 * 
	 * @param knownUsers names of the users that are known to the remote server
	 * @param repository the repository adapter instance
	 * @param tool the current tool
	 * @throws IOException if there's an error processing the repository user list
	 */
	public ProjectAccessPanel(String[] knownUsers, RepositoryAdapter repository, PluginTool tool)
			throws IOException {

		this(knownUsers, repository.getServer().getUser(), Arrays.asList(repository.getUserList()),
			repository.getName(), repository.getServer().anonymousAccessAllowed(),
			repository.anonymousAccessAllowed(), tool);
	}

	/**
	 * Constructs a new panel from the given arguments.
	 * 
	 * @param knownUsers names of the users that are known to the remote server
	 * @param currentUser the current user
	 * @param allUsers all users known to the repository
	 * @param repositoryName the name of the repository
	 * @param anonymousServerAccessAllowed true if the server allows anonymous access
	 * @param anonymousAccessEnabled true if the repository allows anonymous access 
	 * (ignored if anonymousServerAccessAllowed is false)
	 * @param tool the current tool
	 */
	public ProjectAccessPanel(String[] knownUsers, String currentUser, List<User> allUsers,
			String repositoryName, boolean anonymousServerAccessAllowed,
			boolean anonymousAccessEnabled, PluginTool tool) {

		super(new BorderLayout());

		this.currentUser = currentUser;
		this.origProjectUserList = allUsers;
		this.origAnonymousAccessEnabled = anonymousAccessEnabled;
		this.repositoryName = repositoryName;
		this.tool = tool;

		createMainPanel(knownUsers, anonymousServerAccessAllowed);
	}

	@Override
	public boolean isValidInformation() {
		return true;
	}

	@Override
	public String getTitle() {
		return "Specify Users for Repository " + repositoryName;
	}

	@Override
	public void initialize() {
		userAccessPanel.resetUserList();
		if (anonymousAccessCB != null) {
			anonymousAccessCB.setSelected(origAnonymousAccessEnabled);
		}
	}

	@Override
	public HelpLocation getHelpLocation() {
		if (helpLoc != null) {
			return helpLoc;
		}
		return new HelpLocation(GenericHelpTopics.FRONT_END, "UserAccessList");
	}

	/**
	 * Sets the help location.
	 * 
	 * @param helpLoc the help location
	 */
	void setHelpLocation(HelpLocation helpLoc) {
		this.helpLoc = helpLoc;
	}

	/**
	 * Returns a list of all users with permission to access the project.
	 * 
	 * @return the list of users
	 */
	User[] getProjectUsers() {
		return userAccessPanel.getProjectUsers();
	}

	/**
	 * Returns true if anonymous access is allowed by the repository.
	 * 
	 * @return true if allowed
	 */
	boolean allowAnonymousAccess() {
		return anonymousAccessCB != null && anonymousAccessCB.isSelected();
	}

	/**
	 * Returns the repository name.
	 * 
	 * @return the repository name
	 */
	String getRepositoryName() {
		return repositoryName;
	}

	/**
	 * Creates the main gui panel, containing the known users, button, and user access 
	 * panels.
	 */
	protected void createMainPanel(String[] knownUsers, boolean anonymousServerAccessAllowed) {

		JPanel mainPanel = new JPanel();
		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.X_AXIS));

		knownUsersPanel = new KnownUsersPanel(Arrays.asList(knownUsers));
		userAccessPanel = new UserAccessPanel(currentUser);
		addRemoveButtonPanel = new ButtonPanel();

		mainPanel.add(knownUsersPanel);
		mainPanel.add(addRemoveButtonPanel);
		mainPanel.add(userAccessPanel);

		add(mainPanel, BorderLayout.CENTER);

		if (anonymousServerAccessAllowed) {
			anonymousAccessCB = new GCheckBox("Allow Anonymous Access", origAnonymousAccessEnabled);
			anonymousAccessCB.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 0));
			add(anonymousAccessCB, BorderLayout.SOUTH);
		}
	}

	/**
	 * Panel containing the buttons for adding/removing users from the current project.
	 */
	class ButtonPanel extends JPanel {

		private JButton addButton;
		private JButton addAllButton;
		private JButton removeButton;
		private JButton removeAllButton;

		public ButtonPanel() {

			addButton = new JButton("Add >>");
			addButton.setEnabled(false);
			addButton.addActionListener(e -> {
				userAccessPanel.addUsers(knownUsersPanel.getSelectedUsers());
			});

			addAllButton = new JButton("Add All");
			addAllButton.addActionListener(e -> {
				userAccessPanel.addUsers(knownUsersPanel.getAllUsers());
				knownUsersPanel.clearSelection();
			});
			addAllButton.setEnabled(true);

			removeButton = new JButton("<< Remove");
			removeButton.setEnabled(false);
			removeButton.addActionListener(e -> userAccessPanel.removeSelectedUsers());

			removeAllButton = new JButton("Remove All");
			removeAllButton.addActionListener(e -> {
				userAccessPanel.removeAllUsers();
				knownUsersPanel.clearSelection();
			});
			removeAllButton.setEnabled(true);

			JPanel panel = ButtonPanelFactory.createButtonPanel(
				new JButton[] { addButton, addAllButton, removeButton, removeAllButton }, 5);
			panel.setMinimumSize(panel.getPreferredSize());

			// Set up a listener so this panel can update its state when something in the user
			// permissions list has been selected.
			userAccessPanel.getTable().getSelectionModel().addListSelectionListener(e -> {
				if (e.getValueIsAdjusting()) {
					return;
				}
				updateState();
			});

			// Need to update the known users panel whenever a user is added/removed from the
			// access panel (the icon showing whether they're in the project or not needs
			// to be updated).
			userAccessPanel.tableModel.addTableModelListener(e -> {
				knownUsersPanel.repaint();
			});

			// Set up a listener so this panel can update its state when something in the known
			// users list has been selected.
			knownUsersPanel.getList().getSelectionModel().addListSelectionListener(e -> {
				if (e.getValueIsAdjusting()) {
					return;
				}
				updateState();
			});

			add(panel);
		}

		/**
		 * Ensures that all buttons are enabled/disabled appropriately based on the current
		 * selections.
		 * <p>
		 * Note that the "add all" and "remove all" buttons are always enabled so they aren't addressed
		 * here.
		 */
		public void updateState() {
			updateAddButtonState();
			updateRemoveButtonState();
		}

		/**
		 * Updates the 'remove' button state based on the selections in the user access panel.
		 */
		private void updateRemoveButtonState() {
			boolean enabled = false;

			List<String> selectedUserNames = userAccessPanel.getSelectedUsers();

			if (selectedUserNames.isEmpty()) {
				enabled = false;
			}
			else if (selectedUserNames.size() == 1) {
				if (selectedUserNames.get(0).equals(currentUser)) {
					enabled = false;
				}
				else {
					enabled = true;
				}
			}
			else {
				enabled = true;
			}

			removeButton.setEnabled(enabled);
		}

		/**
		 * Updates the 'add' button state based on the selections in the known users panel.
		 */
		private void updateAddButtonState() {
			boolean enabled = false;

			List<String> selectedUserNames = knownUsersPanel.getSelectedUsers();
			for (String user : selectedUserNames) {
				if (!userAccessPanel.isInProjectAccessList(user)) {
					enabled = true;
					break;
				}
			}
			addButton.setEnabled(enabled);
		}
	}

	/**
	 * Panel for displaying project users and their access permissions. Users with admin rights 
	 * can edit the permissions of other users.
	 */
	class UserAccessPanel extends JPanel {

		private GTable table;
		private UserAccessTableModel tableModel;

		/**
		 * Creates a new user access panel.
		 * 
		 * @param user the current user
		 * @param userList the list of users to display in the table
		 */
		UserAccessPanel(String user) {
			setLayout(new BorderLayout());

			tableModel = new UserAccessTableModel(user, origProjectUserList, tool);
			table = new GTable(tableModel);
			table.setShowGrid(false);
			table.setSelectionBackground(SELECTION_BG_COLOR);
			table.setSelectionForeground(SELECTION_FG_COLOR);
			table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
			table.setBorder(BorderFactory.createEmptyBorder());

			JScrollPane sp = new JScrollPane(table);
			sp.setBorder(BorderFactory.createTitledBorder("Project Users"));
			sp.setBackground(getBackground());
			add(sp, BorderLayout.CENTER);

			setPreferredSize(new Dimension(400, 200));
		}

		/**
		 * Returns the user table.
		 * 
		 * @return the user table
		 */
		GTable getTable() {
			return table;
		}

		/**
		 * Reset user list with the original set of users and permissions
		 */
		void resetUserList() {
			tableModel.setUserList(origProjectUserList);
		}

		/**
		 * Returns a list of all selected users in the table.
		 * 
		 * @return list of user names
		 */
		List<String> getSelectedUsers() {

			List<String> users = new ArrayList<>();
			int[] selectedRows = table.getSelectedRows();
			for (int i = 0; i < selectedRows.length; i++) {
				User user = tableModel.getRowObject(selectedRows[i]);
				users.add(user.getName());
			}

			return users;
		}

		/**
		 * Returns true if the given user is in the project access list.
		 * 
		 * @param name the user name
		 * @return true if already has project access
		 */
		boolean isInProjectAccessList(String name) {

			List<User> usersInProject = tableModel.getDataSource();
			for (User user : usersInProject) {
				if (user.getName().equals(name)) {
					return true;
				}
			}

			return false;
		}

		/**
		 * Returns a list of all users who have project access.
		 * 
		 * @return list of users
		 */
		User[] getProjectUsers() {
			User[] users = new User[tableModel.getModelData().size()];
			return tableModel.getModelData().toArray(users);
		}

		/**
		 * Removes all users from the table.
		 */
		private void removeAllUsers() {

			ArrayList<User> list = new ArrayList<>();

			// Remove all users, except the user entry that represents the one
			// doing the removing.
			for (User user : tableModel.getModelData()) {
				if (user.getName().equals(currentUser)) {
					continue;
				}
				list.add(user);
			}

			tableModel.removeUsers(list);
		}

		/**
		 * Removes only the selected users from the table.
		 */
		private void removeSelectedUsers() {

			ArrayList<User> users = new ArrayList<>();

			// Remove all selected users, except the user entry that represents the one
			// doing the removing.
			for (int selectedRow : table.getSelectedRows()) {
				User user = tableModel.getRowObject(selectedRow);
				if (user.getName().equals(currentUser)) {
					continue;
				}
				users.add(user);
			}

			tableModel.removeUsers(users);
		}

		/**
		 * Adds the give list of users to the table.
		 * 
		 * @param users the users to add
		 */
		private void addUsers(List<String> users) {

			ArrayList<User> list = new ArrayList<>();

			// Only add the user if they don't already have access.
			for (String user : users) {
				if (!isInProjectAccessList(user)) {
					list.add(new User(user, User.WRITE));
				}
			}

			tableModel.addUsers(list);
		}
	}

	/**
	 * Panel for displaying the list of users with repository access.
	 */
	class KnownUsersPanel extends JPanel {
		private static final int DEFAULT_USERLIST_ROWS_TO_SHOW = 20;

		private JList<String> userList;
		private DefaultListModel<String> listModel;

		/**
		 * Creates a new users panel.
		 * 
		 * @param users list of users to display
		 */
		KnownUsersPanel(List<String> users) {

			setLayout(new BorderLayout());

			users.sort(String::compareToIgnoreCase);

			listModel = new DefaultListModel<>();
			for (String user : users) {
				listModel.addElement(user);
			}

			userList = new JList<>(listModel);
			userList.setSelectionBackground(SELECTION_BG_COLOR);
			userList.setSelectionForeground(SELECTION_FG_COLOR);
			userList.setCellRenderer(new UserListCellRenderer());

			JScrollPane sp = new JScrollPane(userList);
			sp.setBorder(BorderFactory.createTitledBorder("Known Users"));
			sp.setOpaque(false);

			// Set the minimum dimensions of the scroll pane so we can't collapse it.
			Dimension d = userList.getPreferredSize();
			d.width = 100;
			d.height =
				Math.min(userList.getFixedCellHeight() * DEFAULT_USERLIST_ROWS_TO_SHOW, d.height);
			sp.setPreferredSize(d);
			sp.setMinimumSize(new Dimension(100, 200));

			add(sp, BorderLayout.CENTER);
		}

		/**
		 * Returns a list of selected users
		 * 
		 * @return list of user names
		 */
		List<String> getSelectedUsers() {
			return userList.getSelectedValuesList();
		}

		/**
		 * Returns the user list.
		 * 
		 * @return the user list
		 */
		JList<String> getList() {
			return userList;
		}

		/**
		 * Returns a list of all users in the panel
		 * 
		 * @return list of user names
		 */
		List<String> getAllUsers() {
			List<String> allUsers = CollectionUtils.asList(listModel.elements());
			return allUsers;
		}

		/**
		 * Clears any user selection in the panel.
		 */
		void clearSelection() {
			userList.getSelectionModel().clearSelection();
		}

		/**
		 * Renderer for the {@link KnownUsersPanel}. This is to ensure that we render the
		 * correct icon for each user in the list
		 */
		private class UserListCellRenderer extends GListCellRenderer<String> {

			private Icon icon;
			private Icon inProjectIcon;

			UserListCellRenderer() {
				icon = ResourceManager.loadImage("images/EmptyIcon.gif");
				inProjectIcon = ResourceManager.loadImage("images/user.png");
				icon = ResourceManager.getScaledIcon(icon, inProjectIcon.getIconWidth(),
					inProjectIcon.getIconHeight());
			}

			@Override
			public Component getListCellRendererComponent(JList<? extends String> list,
					String username, int index, boolean isSelected, boolean cellHasFocus) {

				super.getListCellRendererComponent(list, username, index, isSelected, cellHasFocus);

				if (userAccessPanel != null) {
					setIcon(userAccessPanel.isInProjectAccessList(username) ? inProjectIcon : icon);
				}

				return this;
			}
		}
	}
}
