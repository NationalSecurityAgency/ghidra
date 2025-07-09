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
import java.util.function.Consumer;
import java.util.function.Predicate;

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
public class Loaded<T extends DomainObject> implements AutoCloseable {

	protected final T domainObject;
	protected final String name;
	protected Project project;
	protected String projectFolderPath;
	protected Object loadedConsumer;

	protected DomainFile domainFile;

	/**
	 * Creates a new {@link Loaded} object.
	 * <p>
	 * This object needs to be {@link #close() closed} when done with it.
	 * 
	 * @param domainObject The loaded {@link DomainObject}
	 * @param name The name of the loaded {@link DomainObject}.  If a {@link #save(TaskMonitor)} 
	 *   occurs, this will attempted to be used for the resulting {@link DomainFile}'s name.
	 * @param project If not null, the project this will get saved to during a 
	 *   {@link #save(TaskMonitor)} operation
	 * @param projectFolderPath The project folder path this will get saved to during a 
	 *   {@link #save(TaskMonitor)} operation.  If null or empty, the root project folder will be 
	 *   used.
	 * @param consumer A reference to the object "consuming" the returned {@link Loaded} 
	 *   {@link DomainObject}, used to ensure the underlying {@link DomainObject} is only closed 
	 *   when every consumer is done with it (see {@link #close()}). NOTE:  Wrapping a 
	 *   {@link DomainObject} in a {@link Loaded} transfers responsibility of releasing the 
	 *   given {@link DomainObject} to this {@link Loaded}'s {@link #close()} method. 
	 */
	public Loaded(T domainObject, String name, Project project, String projectFolderPath,
			Object consumer) {
		this.domainObject = domainObject;
		this.name = name;
		this.project = project;
		this.loadedConsumer = consumer;
		setProjectFolderPath(projectFolderPath);
	}

	/**
	 * Gets the loaded {@link DomainObject}.
	 * <p>
	 * NOTE: The given It is the responsibility of the caller to properly 
	 * {@link DomainObject#release(Object) release} it when done. This
	 * {@link DomainObject#release(Object)} does not replace the requirement to 
	 * {@link #close()} the {@link Loaded} object when done.
	 * 
	 * @param consumer A new reference to the object "consuming" the returned {@link DomainObject},
	 *   used to ensure the underlying {@link DomainObject} is only released when every consumer is
	 *   done with it (see {@link DomainObject#release(Object)}). NOTE: This method adds the given
	 *   consumer to the returned {@link DomainObject}, requiring an explicit 
	 *   {@link DomainObject#release(Object)} to be called on the return value (this 
	 *   {@link Loaded} must also still be {@link #close() closed}).
	 * @return The loaded {@link DomainObject}
	 */
	public T getDomainObject(Object consumer) {
		domainObject.addConsumer(consumer);
		return domainObject;
	}
	
	/**
	 * Gets the loaded {@link DomainObject} with unsafe resource management. Temporarily exists
	 * to provide backwards compatibility.
	 * 
	 * @return The loaded {@link DomainObject}
	 * @deprecated This class's internal {@link DomainObject} is now cleaned up with the 
	 *   {@link #close()} method.  If the {@link DomainObject} needs to be retrieved from this 
	 *   class, instead use {@link #getDomainObject(Object)} and independently clean up the new
	 *   reference with a separate call to {@link DomainObject#release(Object)}.
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public T getDomainObject() {
		return domainObject;
	}

	/**
	 * Gets the loaded {@link DomainObject}'s type
	 * 
	 * @return the loaded {@link DomainObject}'s type
	 */
	public Class<? extends DomainObject> getDomainObjectType() {
		return domainObject.getClass();
	}

	/**
	 * Safely applies the given operation to the loaded {@link DomainObject} without the need to 
	 * worry about resource management
	 * 
	 * @param operation The operation to apply to the loaded {@link DomainObject}
	 */
	public void apply(Consumer<T> operation) {
		operation.accept(domainObject);
	}

	/**
	 * Safely tests the given predicate on the loaded {@link DomainObject} without the need to 
	 * worry about resource management
	 * 
	 * @param predicate The predicate to test
	 * @return The result of the test
	 */
	public boolean check(Predicate<T> predicate) {
		return predicate.test(domainObject);
	}

	/**
	 * Gets the name of the loaded {@link DomainObject}.  If a {@link #save(TaskMonitor)} occurs, 
	 * this will attempted to be used for the resulting {@link DomainFile}'s name.
	 * 
	 * @return the name of the loaded {@link DomainObject}
	 */
	public String getName() {
		return name;
	}

	/**
	 * Gets the {@link Project} this will get saved to during a {@link #save(TaskMonitor)} operation
	 *
	 *@return The {@link Project} this will get saved to during a {@link #save(TaskMonitor)} 
	 *  operation (could be null)
	 */
	public Project getProject() {
		return project;
	}

	/**
	 * Gets the project folder path this will get saved to during a {@link #save(TaskMonitor)} 
	 * operation.
	 * <p>
	 * NOTE: The returned path will always end with a "/".
	 * 
	 * @return the project folder path
	 */
	public String getProjectFolderPath() {
		return projectFolderPath;
	}

	/**
	 * Sets the project folder path this will get saved to during a {@link #save(TaskMonitor)} 
	 * operation.
	 * 
	 * @param projectFolderPath The project folder path this will get saved to during a 
	 *   {@link #save(TaskMonitor)} operation.  If null or empty, the root project folder will be 
	 *   used.
	 */
	public void setProjectFolderPath(String projectFolderPath) {
		if (projectFolderPath == null || projectFolderPath.isBlank()) {
			projectFolderPath = "/";
		}
		else if (!projectFolderPath.endsWith("/")) {
			projectFolderPath += "/";
		}
		this.projectFolderPath = projectFolderPath;
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
	 * @param monitor A cancelable task monitor
	 * @return The {@link DomainFile} where the save happened
	 * @throws CancelledException if the operation was cancelled
	 * @throws ClosedException if the loaded {@link DomainObject} was already closed
	 * @throws IOException If there was an IO-related error, an invalid name was specified, or it
	 *   was already successfully saved and still exists
	 */
	public DomainFile save(TaskMonitor monitor)
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
			// Allow the save to proceed.
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
	 * {@link #save(TaskMonitor) saved}
	 * 
	 * @return The loaded {@link DomainObject}'s associated saved {@link DomainFile}, or null if 
	 *   was not saved
	 * @throws FileNotFoundException If the loaded {@link DomainObject} was saved but the associated
	 *   {@link DomainFile} no longer exists
	 * @see #save(TaskMonitor)
	 */
	public DomainFile getSavedDomainFile() throws FileNotFoundException {
		if (domainFile != null && !domainFile.exists()) {
			throw new FileNotFoundException("Saved DomainFile no longer exists: " + domainFile);
		}
		return domainFile;
	}

	/**
	 * Unsafely notifies the loaded {@link DomainObject} that the specified consumer is no longer
	 * using it. Temporarily exists to provide backwards compatibility.
	 * 
	 * @param consumer the consumer
	 * @deprecated Use {@link #close()} instead
	 */
	@Deprecated(since = "12.0", forRemoval = true)
	public void release(Object consumer) {
		if (!domainObject.isClosed() && domainObject.isUsedBy(consumer)) {
			domainObject.release(consumer);
		}
	}

	/**
	 * Closes this {@link Loaded} {@link DomainObject} and releases the reference on the object
	 * consuming it.
	 * <p>
	 * NOTE: Any {@link DomainObject}s obtained via {@link #getDomainObject(Object)} must still be
	 * explicitly {@link DomainObject#release(Object) released} after calling this method, since 
	 * they were obtained with their own consumers.
	 */
	@Override
	public void close() {
		if (loadedConsumer != null && !domainObject.isClosed() &&
			domainObject.isUsedBy(loadedConsumer)) {
			domainObject.release(loadedConsumer);
		}
	}

	@Override
	public String toString() {
		return getProjectFolderPath() + getName();
	}
}
