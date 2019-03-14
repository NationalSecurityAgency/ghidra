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

import ghidra.framework.store.FileSystem;

import java.lang.reflect.Method;

/**
 * Adapter for the domain folder change listener.
 * @see DomainFolderChangeListener for details regarding listener use
 */
public abstract class DomainFolderListenerAdapter implements DomainFolderChangeListener {

	private final boolean enableStateChangeCallback;

	protected DomainFolderListenerAdapter() {
		// Only issue stateChanged callback if method has been overridden
		boolean foundStateChangedMethod = false;
		try {
			Method method =
				getClass().getMethod("stateChanged", String.class, String.class, boolean.class);
			if (!method.getDeclaringClass().equals(DomainFolderListenerAdapter.class)) {
				foundStateChangedMethod = true;
			}
		}
		catch (SecurityException e) {
			// ignore
		}
		catch (NoSuchMethodException e) {
			// ignore
		}
		enableStateChangeCallback = foundStateChangedMethod;
	}

	/**
	 * Provides a consolidated callback for those listener methods which have not been
	 * overridden.  This callback is NOT invoked for the following callbacks:
	 * <ul>
	 * <li>domainFolderSetActive</li>
	 * <li>domainFileObjectReplaced</li>
	 * <li>domainFileObjectOpenedForUpdate</li>
	 * <li>domainFileObjectClosed</li>
	 * </ul>
	 * @param affectedNewPath new path of affected folder/file, or null if item was 
	 * removed (see affectedOldPath)
	 * @param affectedOldPath original path of affected folder/file, or null for new
	 * item (see affectedOldPath)
	 * @param isFolder true if affected item is/was a folder
	 */
	public void stateChanged(String affectedNewPath, String affectedOldPath, boolean isFolder) {
		// do nothing
	}

	private String getPathname(DomainFolder parentFolder, String childName) {
		String path = parentFolder.getPathname();
		if (path.length() != FileSystem.SEPARATOR.length()) {
			path += FileSystem.SEPARATOR;
		}
		path += childName;
		return path;
	}

	@Override
	public void domainFolderAdded(DomainFolder folder) {
		if (enableStateChangeCallback)
			stateChanged(folder.getPathname(), null, true);
	}

	@Override
	public void domainFileAdded(DomainFile file) {
		if (enableStateChangeCallback)
			stateChanged(file.getPathname(), null, false);
	}

	@Override
	public void domainFolderRemoved(DomainFolder parent, String name) {
		if (enableStateChangeCallback)
			stateChanged(null, getPathname(parent, name), true);
	}

	@Override
	public void domainFileRemoved(DomainFolder parent, String name, String fileID) {
		if (enableStateChangeCallback)
			stateChanged(null, getPathname(parent, name), false);
	}

	@Override
	public void domainFolderRenamed(DomainFolder folder, String oldName) {
		if (enableStateChangeCallback)
			stateChanged(getPathname(folder.getParent(), oldName), folder.getPathname(), true);
	}

	@Override
	public void domainFileRenamed(DomainFile file, String oldName) {
		if (enableStateChangeCallback)
			stateChanged(getPathname(file.getParent(), oldName), file.getPathname(), false);
	}

	@Override
	public void domainFolderMoved(DomainFolder folder, DomainFolder oldParent) {
		if (enableStateChangeCallback)
			stateChanged(folder.getPathname(), getPathname(oldParent, folder.getName()), true);
	}

	@Override
	public void domainFileMoved(DomainFile file, DomainFolder oldParent, String oldName) {
		if (enableStateChangeCallback)
			stateChanged(file.getPathname(), getPathname(oldParent, oldName), false);
	}

	@Override
	public void domainFolderSetActive(DomainFolder folder) {
		// do nothing
	}

	@Override
	public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
		if (enableStateChangeCallback) {
			String path = file.getPathname();
			stateChanged(path, path, false);
		}
	}

	@Override
	public void domainFileObjectReplaced(DomainFile file, DomainObject oldObject) {
		// do nothing
	}

	@Override
	public void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object) {
		// do nothing
	}

	@Override
	public void domainFileObjectClosed(DomainFile file, DomainObject object) {
		// do nothing
	}
}
