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
package ghidra.app.plugin.core.datamgr;

import ghidra.app.plugin.core.datamgr.archive.InvalidArchive;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;
import ghidra.program.model.dtarchive.DataTypeStore;
import ghidra.program.model.listing.Program;

/**
 * Interface for notifications when archives change in the archive manager
 */
public interface ArchiveManagerListener {
	/**
	 * Called when a new Archive is opened.
	 * @param archive the new archive that was opened.
	 */
	public void archiveOpened(PersistentDataTypeArchive archive);

	/**
	 * Called when an archive is closed.
	 * @param archive the archive that was closed.
	 */
	public void archiveClosed(PersistentDataTypeArchive archive);

	/**
	 * Called when a new program is activated
	 * @param program the program that is activated
	 */
	public void programOpened(Program program);

	/**
	 * Called when the current program is deactivated
	 * @param program the program that is being deactivated
	 */
	public void programClosed(Program program);

	/**
	 * Called when the tool attempts to open a file or project archive that is referenced by
	 * a program, but can't be found. This creates a object that actions can operate on to
	 * either attempt to find it or use it to remove the references from a program.
	 * @param invalidArchive the InvalidArchive object that describes what the program was trying
	 * to open.
	 */
	public void invalidArchiveAdded(InvalidArchive invalidArchive);

	/**
	 * Called when an invalid archive is removed from the tool.
	 * @param invalidArchive the invalid archive object that was removed from the tool
	 */
	public void invalidArchiveRemoved(InvalidArchive invalidArchive);

	/**
	 * Notification that a change to the datatypeStore has occurred. Could be a datatype or 
	 * category was added, changed, or deleted. Could also mean that the changes were saved to
	 * the backing store or the that a save as operation occurred.
	 * @param dataTypeStore The store whose state changed
	 */
	public void stateChanged(DataTypeStore dataTypeStore);
}
