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
package ghidra.app.plugin.core.datamgr.archive;

import ghidra.program.model.data.DataTypeManager;

public interface ArchiveManagerListener {
	/**
	 * Called when a new Archive is opened.
	 * @param archive the new archive that was opened.
	 */
	void archiveOpened(Archive archive);

	/**
	 * Called when an archive is closed.
	 * @param archive the archive that was closed.
	 */
	void archiveClosed(Archive archive);

	/**
	 * Called when the edited state of the archive has changed, for example, when an archive
	 * has had a data type or category added or removed.
	 */
	public void archiveStateChanged(Archive archive);

	/**
	 * Called when the {@link DataTypeManager} of the archive has changed.  This can happen when
	 * an archive is locked or unlocked.
	 */
	public void archiveDataTypeManagerChanged(Archive archive);
}
