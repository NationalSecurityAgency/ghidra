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
package ghidra.framework.remote;

import java.io.Serializable;

/**
 * Container class for the user name and the permission type: READ_ONLY,
 * WRITE, or ADMIN.
 */
public class User implements Comparable<User>, Serializable {

	public final static long serialVersionUID = 2L;

	/**
	 * Name associated with anonymous user
	 */
	public static final String ANONYMOUS_USERNAME = "-anonymous-";

	/**
	 * Value corresponding to Read-only permission for a repository user.
	 */
	public final static int READ_ONLY = 0;

	/**
	 * Value corresponding to Write permission for a repository user.
	 */
	public final static int WRITE = 1;

	/**
	 * Value corresponding to Administrative permission for a repository user.
	 */
	public final static int ADMIN = 2;

	private final static String[] types = { "read-only", "write", "admin" };

	private int permission;
	private String name;

	/**
	 * Constructor.
	 * @param name user id/name
	 * @param permission permission value (READ_ONLY, WRITE or ADMIN)
	 */
	public User(String name, int permission) {
		this.name = name;
		if (permission < READ_ONLY || permission > ADMIN) {
			throw new IllegalArgumentException(
				"Invalid type: " + permission + "; must be READ_ONLY, WRITE, or ADMIN");
		}
		this.permission = permission;
	}

	/**
	 * Returns user id/name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns true if permission is READ_ONLY.
	 */
	public boolean isReadOnly() {
		return permission == READ_ONLY;
	}

	/**
	 * Return true if this user has permission of WRITE or ADMIN.
	 */
	public boolean hasWritePermission() {
		return permission == WRITE || permission == ADMIN;
	}

	/**
	 * Returns true if permission is ADMIN.
	 */
	public boolean isAdmin() {
		return permission == ADMIN;
	}

	/**
	 * Returns the permission value assigned this user.
	 */
	public int getPermissionType() {
		return permission;
	}

	/*
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer();
		buf.append(name);
		buf.append(" (");
		buf.append(types[permission]);
		buf.append(")");
		return buf.toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + permission;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		User other = (User) obj;
		if (name == null) {
			if (other.name != null)
				return false;
		}
		else if (!name.equals(other.name))
			return false;
		if (permission != other.permission)
			return false;
		return true;
	}

	@Override
	public int compareTo(User other) {
		if (name == null) {
			if (other.name != null)
				return -1;
		}
		else if (other.name != null) {
			return 1;
		}
		int rc = name.compareTo(other.name);
		if (rc == 0) {
			return permission - other.permission;
		}
		return rc;
	}
}
