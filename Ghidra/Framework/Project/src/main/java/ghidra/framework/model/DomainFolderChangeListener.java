/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.model;

/**
 * Methods for notifications when changes are made to a domain folder or
 * a domain file.
 */
public interface DomainFolderChangeListener {

	/**
	 * Notification that a folder is added to parent.
	 * @param folder domain folder which was just added.
	 */
	public void domainFolderAdded(DomainFolder folder);

	/**
	 * Notification that a file is added to parent folder. You can
	 * get the parent from the file.
	 * @param file domain file which was just added.
	 */
	public void domainFileAdded(DomainFile file);

	/**
	 * Notification that a domain folder is removed.
	 * @param parent domain folder which contained the folder that was just removed.
	 * @param name the name of the folder that was removed.
	 */
	public void domainFolderRemoved(DomainFolder parent, String name);

	/**
	 * Notification that a file was removed
	 * @param parent domain folder which contained the file that was just removed.
	 * @param name the name of the file that was removed.
	 * @param fileID file ID or null
	 */
	public void domainFileRemoved(DomainFolder parent, String name, String fileID);

	/**
	 * Notify listeners when a domain folder is renamed.
	 * @param folder folder that was renamed
	 * @param oldName old name of folder
	 */
	public void domainFolderRenamed(DomainFolder folder, String oldName);

	/**
	 * Notification that the domain file was renamed.
	 * @param file file that was renamed
	 * @param oldName old name of the file
	 */
	public void domainFileRenamed(DomainFile file, String oldName);

	/**
	 * Notification that the domain folder was moved.
	 * @param folder the folder (after move)
	 * @param oldParent original parent folder
	 */
	public void domainFolderMoved(DomainFolder folder, DomainFolder oldParent);

	/**
	 * Notification that the domain file was moved.
	 * @param file the file (after move)
	 * @param oldParent original parent folder
	 */
	public void domainFileMoved(DomainFile file, DomainFolder oldParent, String oldName);

	/**
	 * Notification that the setActive() method on the folder was called.
	 */
	public void domainFolderSetActive(DomainFolder folder);

	/**
	 * Notification that the status for a domain file has changed.
	 * @param file file whose status has changed.
	 * @param fileIDset if true indicates that the previously missing fileID has been
	 * established for the specified file.
	 */
	public void domainFileStatusChanged(DomainFile file, boolean fileIDset);

	/**
	 * Notification that a new version of the domain object exists and the
	 * current one is no longer valid. Existing consumers should be immediately
	 * released and no additional use of the oldObject is permitted once this 
	 * method returns.  This is only called for domain objects which were
	 * opened for update.
	 * @param file file whose object was replaced
	 * @param oldObject old object that was replaced
	 */
	public void domainFileObjectReplaced(DomainFile file, DomainObject oldObject);

	/**
	 * Notification that a domain file has been opened for update.
	 * @param file domain file
	 * @param object domain object open for update
	 */
	public void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object);

	/**
	 * Notification that a domain file previously open for update is in the process of closing.
	 * @param file domain file
	 * @param object domain object which was open for update
	 */
	public void domainFileObjectClosed(DomainFile file, DomainObject object);

}
