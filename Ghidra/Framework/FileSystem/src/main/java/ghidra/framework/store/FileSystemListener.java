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
package ghidra.framework.store;

/**
 * <code>FileSystemListener</code> provides a listener the ability 
 * to be notified of folder and file changes within a FileSystem.
 */
public interface FileSystemListener {

	/**
	 * Notification that a new folder was created.
	 * @param parentPath the path of the folder that contains the new folder
	 * @param name the name of the new folder
	 */
	void folderCreated(String parentPath, String name);

	/**
	 * Notification that a new folder item was created.
	 * @param parentPath the path of the folder that contains the new item.
	 * @param name the name of the new item.
	 */
	void itemCreated(String parentPath, String name);

	/**
	 * Notification that a folder was deleted.
	 * @param parentPath the path of the folder that contained the deleted folder.
	 * @param folderName the name of the folder that was deleted.
	 */
	void folderDeleted(String parentPath, String folderName);

	/**
	 * Notification that a folder was moved.
	 * @param parentPath the path of the folder that used to contain the moved folder.
	 * @param folderName the name of the folder that was moved.
	 * @param newParentPath the path of the folder that now contains the moved folder.
	 */
	void folderMoved(String parentPath, String folderName, String newParentPath);

	/**
	 * Notification that a folder was renamed.
	 * @param parentPath the path of the folder containing the folder that was renamed.
	 * @param oldFolderName the old name of the folder.
	 * @param newFolderName the new name of the folder.
	 */
	void folderRenamed(String parentPath, String oldFolderName, String newFolderName);

	/**
	 * Notification that a folder item was deleted.
	 * @param folderPath the path of the folder that contained the deleted item.
	 * @param itemName the name of the item that was deleted.
	 */
	void itemDeleted(String folderPath, String itemName);

	/**
	 * Notification that an item was renamed.
	 * @param folderPath the path of the folder that contains the renamed item
	 * @param oldItemName the old name of the item.
	 * @param newItemName the new name of the item.
	 */
	void itemRenamed(String folderPath, String oldItemName, String newItemName);

	/**
	 * Notification that an item was moved.
	 * @param parentPath the path of the folder that used to contain the item.
	 * @param name the name of the item that was moved.
	 * @param newParentPath the path of the folder that the item was moved to.
	 * @param newName the new name of the item.
	 */
	void itemMoved(String parentPath, String name, String newParentPath, String newName);
	
	/**
	 * Notfication that an item's state has changed.
	 * @param parentPath the path of the folder containing the item.
	 * @param itemName the name of the item that has changed.
	 */
	void itemChanged(String parentPath, String itemName);
	
	/**
	 * Perform a full refresh / synchronization
	 */
	void syncronize();

}
