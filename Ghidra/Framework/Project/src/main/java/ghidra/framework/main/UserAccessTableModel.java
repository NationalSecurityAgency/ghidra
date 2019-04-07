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

import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.remote.User;

/**
 * Table model for managing a list of Ghidra users associated with a project, and
 * their access permissions. The permissions (read-only, read/write, admin) are rendered
 * as checkboxes that can be selected by users, provided they have admin access.
 *
 */
class UserAccessTableModel extends GDynamicColumnTableModel<User, List<User>> {

	private List<User> users;
	private String currentUser;

	public static final int USERS_COL = 0;
	public static final int READ_ONLY_COL = 1;
	public static final int READ_WRITE_COL = 2;
	public static final int ADMIN_COL = 3;

	/**
	 * Constructs a new table model.
	 *
	 * @param currentUser the name of the current user
	 * @param userList list of all users associated with the current project
	 * @param serviceProvider the service provider
	 */
	public UserAccessTableModel(String currentUser, List<User> userList,
			ServiceProvider serviceProvider) {
		super(serviceProvider);

		this.currentUser = currentUser;
		this.users = new ArrayList<>(userList);
	}

	@Override
	public String getName() {
		return "User Access";
	}

	/**
	 * Invoked when the user has changed one of the access rights checkboxes. When this
	 * happens we have to update the associated User data.
	 */
	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {

		// Shouldn't happen, but do a sanity check.
		if (rowIndex < 0 || rowIndex >= users.size()) {
			return;
		}

		User user = users.get(rowIndex);

		switch (columnIndex) {
			case READ_ONLY_COL:
				user = new User(user.getName(),
					((Boolean) aValue).booleanValue() ? User.READ_ONLY : User.WRITE);
				break;

			case READ_WRITE_COL:
				user = new User(user.getName(),
					((Boolean) aValue).booleanValue() ? User.WRITE : User.READ_ONLY);
				break;

			case ADMIN_COL:
				user = new User(user.getName(),
					((Boolean) aValue).booleanValue() ? User.ADMIN : User.WRITE);
				break;
		}

		users.remove(rowIndex);
		users.add(rowIndex, user);

		refresh();
	}

	/**
	 * The permissions columns in the table should be editable as long as the user
	 * is an admin and is not trying to adjust his/her own permissions.
	 */
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {

		// If the user is not admin, nothing is editable.
		if (!getCurrentUser().isAdmin()) {
			return false;
		}

		switch (columnIndex) {
			case USERS_COL:
				return false;
			case READ_ONLY_COL:
			case READ_WRITE_COL:
			case ADMIN_COL:
				User rowUser = users.get(rowIndex);
				User currentUser = getCurrentUser();
				if (currentUser != null) {
					return currentUser.isAdmin() && !rowUser.equals(currentUser);
				}
		}

		return false;
	}

	@Override
	protected TableColumnDescriptor<User> createTableColumnDescriptor() {

		TableColumnDescriptor<User> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new UserColumn());
		descriptor.addVisibleColumn(new ReadOnlyColumn());
		descriptor.addVisibleColumn(new ReadWriteColumn());
		descriptor.addVisibleColumn(new AdminColumn());

		return descriptor;
	}

	@Override
	public List<User> getDataSource() {
		return users;
	}

	/**
	 * Replaces the contents of this model with a given list of users.
	 *
	 * @param users the user list
	 */
	void setUserList(List<User> users) {
		this.users = users;
		refresh();
	}

	/**
	 * Remove a list of users from the table.
	 *
	 * @param list list of User objects
	 */
	void removeUsers(ArrayList<User> users) {
		this.users.removeAll(users);
		refresh();
	}

	/**
	 * Add a list of users to the table.
	 *
	 * @param users list of User objects
	 */
	void addUsers(ArrayList<User> users) {
		this.users.addAll(users);
		refresh();
	}

	/**
	 * Returns the {@link User} currently using the dialog.
	 *
	 * @return the current user or null if not found
	 */
	private User getCurrentUser() {
		for (User user : users) {
			if (user.getName().equals(currentUser)) {
				return user;
			}
		}
		return null;
	}

	/**
	 * Table column for displaying the user name.
	 */
	class UserColumn extends AbstractDynamicTableColumn<User, String, List<User>> {

		@Override
		public String getColumnName() {
			return "User";
		}

		@Override
		public String getValue(User rowObject, Settings settings, List<User> data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getName();
		}
	}

	/**
	 * Table column for displaying the users read only status.
	 */
	class ReadOnlyColumn extends AbstractDynamicTableColumn<User, Boolean, List<User>> {

		@Override
		public String getColumnName() {
			return "Read Only";
		}

		@Override
		public Boolean getValue(User rowObject, Settings settings, List<User> data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.isReadOnly();
		}
	}

	/**
	 * Table column for displaying the users read/write status.
	 */
	class ReadWriteColumn extends AbstractDynamicTableColumn<User, Boolean, List<User>> {

		@Override
		public String getColumnName() {
			return "Read/Write";
		}

		@Override
		public Boolean getValue(User rowObject, Settings settings, List<User> data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.hasWritePermission() && !rowObject.isAdmin();
		}
	}

	/**
	 * Table column for displaying if the user has admin status.
	 */
	class AdminColumn extends AbstractDynamicTableColumn<User, Boolean, List<User>> {

		@Override
		public String getColumnName() {
			return "Admin";
		}

		@Override
		public Boolean getValue(User rowObject, Settings settings, List<User> data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.isAdmin();
		}
	}

	@Override
	public List<User> getModelData() {
		return users;
	}
}
