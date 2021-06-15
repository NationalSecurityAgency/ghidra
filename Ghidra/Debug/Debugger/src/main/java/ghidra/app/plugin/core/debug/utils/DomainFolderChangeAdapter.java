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
package ghidra.app.plugin.core.debug.utils;

import ghidra.framework.model.*;

public interface DomainFolderChangeAdapter extends DomainFolderChangeListener {
	@Override
	default void domainFileAdded(DomainFile file) {
	}

	@Override
	default void domainFolderAdded(DomainFolder folder) {
	}

	@Override
	default void domainFolderRemoved(DomainFolder parent, String name) {
	}

	@Override
	default void domainFileRemoved(DomainFolder parent, String name, String fileID) {
	}

	@Override
	default void domainFolderRenamed(DomainFolder folder, String oldName) {
	}

	@Override
	default void domainFileRenamed(DomainFile file, String oldName) {
	}

	@Override
	default void domainFolderMoved(DomainFolder folder, DomainFolder oldParent) {
	}

	@Override
	default void domainFileMoved(DomainFile file, DomainFolder oldParent, String oldName) {
	}

	@Override
	default void domainFolderSetActive(DomainFolder folder) {
	}

	@Override
	default void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
	}

	@Override
	default void domainFileObjectReplaced(DomainFile file, DomainObject oldObject) {
	}

	@Override
	default void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object) {
	}

	@Override
	default void domainFileObjectClosed(DomainFile file, DomainObject object) {
	}
}
