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
package ghidra.app.util.opinion;

import java.io.FileNotFoundException;
import java.io.IOException;

import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * A loaded {@link DomainObject} produced by a {@link Loader}.  In addition to storing the loaded
 * {@link DomainObject}, it also stores the {@link Loader}'s desired name and project folder path 
 * for the loaded {@link DomainObject}, should it get saved to a project.
 * 
 * @param <T> The type of {@link DomainObject} that was loaded
 */
public class Loaded<T extends DomainObject> {

	private final T domainObject;
	private final String name;
	private String projectFolderPath;

	private DomainFile domainFile;

	/**
	 * Creates a new {@link Loaded} object
	 * 
	 * @param domainObject The loaded {@link DomainObject}
	 * @param name The name of the loaded {@link DomainObject}.  If a 
	 *   {@link #save(Project, MessageLog, TaskMonitor)} occurs, this will attempted to be used for
	 *   the resulting {@link DomainFile}'s name.
	 * @param projectFolderPath The project folder path this will get saved to during a 
	 *   {@link #save(Project, MessageLog, TaskMonitor)} operation.  If null or empty, the root 
	 *   project folder will be used.
	 */
	public Loaded(T domainObject, String name, String projectFolderPath) {
		this.domainObject = domainObject;
		this.name = name;
		setProjectFolderPath(projectFolderPath);
	}

	/**
	 * Gets the loaded {@link DomainObject}
	 * 
	 * @return The loaded {@link DomainObject}
	 */
	public T getDomainObject() {
		return domainObject;
	}

	/**
	 * Gets the name of the loaded {@link DomainObject}.  If a 
	 * {@link #save(Project, MessageLog, TaskMonitor)} occurs, this will attempted to be used for
	 * the resulting {@link DomainFile}'s name.
	 * 
	 * @return the name of the loaded {@link DomainObject}
	 */
	public String getName() {
		return name;
	}

	/**
	 * Gets the project folder path this will get saved to during a 
	 * {@link #save(Project, MessageLog, TaskMonitor)} operation.
	 * <p>
	 * NOTE: The returned path will always end with a "/".
	 * 
	 * @return the project folder path
	 */
	public String getProjectFolderPath() {
		return projectFolderPath;
	}

	/**
	 * Sets the project folder path this will get saved to during a
	 * {@link #save(Project, MessageLog, TaskMonitor)} operation.
	 * 
	 * @param projectFolderPath The project folder path this will get saved to during a 
	 *   {@link #save(Project, MessageLog, TaskMonitor)} operation.  If null or empty, the root 
	 *   project folder will be used.
	 */
	public void setProjectFolderPath(String projectFolderPath) {
		if (projectFolderPath == null) {
			projectFolderPath = "/";
		}
		else if (!projectFolderPath.endsWith("/")) {
			projectFolderPath += "/";
		}
		this.projectFolderPath = projectFolderPath;
	}

	/**
	 * Notify the loaded {@link DomainObject} that the specified consumer is no longer using it.
	 * When the last consumer invokes this method, the loaded {@link DomainObject} will be closed
	 * and will become invalid.
	 * 
	 * @param consumer the consumer
	 */
	public void release(Object consumer) {
		if (!domainObject.isClosed() && domainObject.isUsedBy(consumer)) {
			domainObject.release(consumer);
		}
	}

	/**
	 * Saves the loaded {@link DomainObject} to the given {@link Project} at this object's 
	 * project folder path, using this object's name.
	 * <p>
	 * If a {@link DomainFile} already exists with the same desired name and project folder path,
	 * the desired name will get a counter value appended to it to avoid a naming conflict.
	 * Therefore, it should not be assumed that the returned {@link DomainFile} will have the same
	 * name as a call to {@link #getName()}.
	 * 
	 * @param project The {@link Project} to save to
	 * @param messageLog The log
	 * @param monitor A cancelable task monitor
	 * @return The {@link DomainFile} where the save happened
	 * @throws CancelledException if the operation was cancelled
	 * @throws ClosedException if the loaded {@link DomainObject} was already closed
	 * @throws IOException If there was an IO-related error, an invalid name was specified, or it
	 *   was already successfully saved and still exists
	 */
	public DomainFile save(Project project, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, ClosedException, IOException {

		if (domainObject.isClosed()) {
			throw new ClosedException(
				"Cannot saved closed DomainObject: " + domainObject.getName());
		}

		try {
			if (getSavedDomainFile() != null) { // 
				throw new IOException("Already saved to " + domainFile);
			}
		}
		catch (FileNotFoundException e) {
			// DomainFile was already saved, but no longer exists.
			// Allow the save to proceeded.
			domainFile = null;
		}

		int uniqueNameIndex = 0;
		String uniqueName = name;
		try {
			DomainFolder programFolder = ProjectDataUtils.createDomainFolderPath(
				project.getProjectData().getRootFolder(), projectFolderPath);
			while (!monitor.isCancelled()) {
				try {
					domainFile = programFolder.createFile(uniqueName, domainObject, monitor);
					return domainFile;
				}
				catch (DuplicateFileException e) {
					uniqueName = name + "." + uniqueNameIndex;
					++uniqueNameIndex;
				}
			}
		}
		catch (InvalidNameException e) {
			throw new IOException(e);
		}
		throw new CancelledException();
	}

	/**
	 * Gets the loaded {@link DomainObject}'s associated {@link DomainFile} that was
	 * {@link #save(Project, MessageLog, TaskMonitor) saved}
	 * 
	 * @return The loaded {@link DomainObject}'s associated saved {@link DomainFile}, or null if 
	 *   was not saved
	 * @throws FileNotFoundException If the loaded {@link DomainObject} was saved but the associated
	 *   {@link DomainFile} no longer exists
	 * @see #save(Project, MessageLog, TaskMonitor)
	 */
	public DomainFile getSavedDomainFile() throws FileNotFoundException {
		if (domainFile != null && !domainFile.exists()) {
			throw new FileNotFoundException("Saved DomainFile no longer exists: " + domainFile);
		}
		return domainFile;
	}

	/**
	 * Deletes the loaded {@link DomainObject}'s associated {@link DomainFile} that was
	 * {@link #save(Project, MessageLog, TaskMonitor) saved}.  This method has no effect if it was
	 * never saved.
	 * <p>
	 * NOTE: The loaded {@link DomainObject} must be {@link #release(Object) released} prior to
	 * calling this method.
	 * 
	 * @param consumer the consumer
	 * @throws IOException If there was an issue deleting the saved {@link DomainFile}
	 * @see #save(Project, MessageLog, TaskMonitor)
	 */
	void deleteSavedDomainFile(Object consumer) throws IOException {
		if (domainFile != null && domainFile.exists()) {
			domainFile.delete();
			domainFile = null;
		}
	}

	@Override
	public String toString() {
		return getProjectFolderPath() + getName();
	}
}
