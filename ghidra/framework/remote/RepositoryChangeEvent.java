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
 * Repository change event (used by server only).
 */
public class RepositoryChangeEvent implements Serializable {

	public final static long serialVersionUID = 1L;

	public static final int REP_NULL_EVENT = -1;

	public static final int REP_FOLDER_CREATED = 0;
	public static final int REP_ITEM_CREATED = 1;
	public static final int REP_FOLDER_DELETED = 2;
	public static final int REP_FOLDER_MOVED = 3;
	public static final int REP_FOLDER_RENAMED = 4;
	public static final int REP_ITEM_DELETED = 5;
	public static final int REP_ITEM_RENAMED = 6;
	public static final int REP_ITEM_MOVED = 7;
	public static final int REP_ITEM_CHANGED = 8;
	public static final int REP_OPEN_HANDLE_COUNT = 9;

	private static final int LAST_TYPE = REP_OPEN_HANDLE_COUNT;

	private static final String[] TYPES = new String[] { "Folder Created", "Item Created",
		"Folder Deleted", "Folder Moved", "Folder Renamed", "Item Deleted", "Item Renamed",
		"Item Moved", "Item Changed", "Open Handle Cnt" };

	public final int type;
	public final String parentPath;
	public final String name;
	public final String newParentPath;
	public final String newName;

	/**
	 * Constructor.
	 * Parameters not applicable to the specified type may be null.
	 * @param type event type
	 * @param parentPath parent folder path for repository item or folder
	 * @param name repository item or folder name
	 * @param newParentPath new parent folder path for repository item or folder
	 * @param newName new repository item or folder name
	 */
	public RepositoryChangeEvent(int type, String parentPath, String name, String newParentPath,
			String newName) {
		this.type = type;
		this.parentPath = parentPath;
		this.name = name;
		this.newParentPath = newParentPath;
		this.newName = newName;
	}

	/*
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		if (type >= 0 && type <= LAST_TYPE) {
			StringBuffer buf = new StringBuffer();
			buf.append("<");
			buf.append(TYPES[type]);
			buf.append(",parentPath=");
			buf.append(parentPath);
			buf.append(",name=");
			buf.append(name);
			buf.append(",newParentPath=");
			buf.append(newParentPath);
			buf.append(",newName=");
			buf.append(newName);
			buf.append(">");
			return buf.toString();
		}
		else if (type == REP_NULL_EVENT) {
			return "<Null Event>";
		}
		return "<Unknown RepositoryChangeEvent>";
	}

}
