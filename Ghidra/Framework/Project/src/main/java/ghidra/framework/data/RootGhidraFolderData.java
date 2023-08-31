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
package ghidra.framework.data;

import ghidra.framework.model.DomainFolderChangeListener;
import ghidra.framework.store.FileSystem;

public class RootGhidraFolderData extends GhidraFolderData {

	RootGhidraFolderData(DefaultProjectData projectData, DomainFolderChangeListener listener) {
		super(projectData, listener);
	}

	@Override
	GhidraFolder getDomainFolder() {
		return new RootGhidraFolder(getProjectData(), getChangeListener());
	}

	/**
	 * Provided for testing use only
	 * @param fs versioned file system
	 */
	void setVersionedFileSystem(FileSystem fs) {
		versionedFileSystem = fs;
	}

	@Override
	boolean privateExists() {
		return true;
	}

	/**
	 * used for testing
	 */
	@Override
	boolean sharedExists() {
		return true;
	}

}
