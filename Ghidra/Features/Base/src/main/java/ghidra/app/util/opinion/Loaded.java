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

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Predicate;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.framework.data.FolderLinkContentHandler;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramLinkContentHandler;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
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
	protected FSRL fsrl;
	protected Project project;
	protected String projectRootPath;
	protected boolean mirrorFsLayout;
	protected Object loadedConsumer;

	protected DomainFile domainFile;

	/**
	 * Creates a new {@link Loaded} object.
	 * <p>
	 * This object needs to be {@link #close() closed} when done with it.
	 * 
	 * @param domainObject The loaded {@link DomainObject}
	 * @param name The name of the loaded {@link DomainObject}. Path information that appears at the
	 *   beginning the name will be appended to the {@code projectRootPath} during a 
	 *   {@link #save(TaskMonitor) operation}.
	 * @param fsrl The {@link FSRL} of the loaded {@link DomainObject}
	 * @param project If not {@code null}, the project this will get saved to during a 
	 *   {@link #save(TaskMonitor)} operation
	 * @param projectRootPath The project folder path that all {@link Loaded} {@link DomainObject}s
	 *   will be {@link #save(TaskMonitor) saved} relative to. If {@code null}, "/" will be used.
	 * @param mirrorFsLayout True if the filesystem layout should be mirrored when 
	 *   {@link #save(TaskMonitor) saving}; otherwise, false
	 * @param consumer A reference to the object "consuming" the returned {@link Loaded} 
	 *   {@link DomainObject}, used to ensure the underlying {@link DomainObject} is only closed 
	 *   when every consumer is done with it (see {@link #close()}). NOTE:  Wrapping a 
	 *   {@link DomainObject} in a {@link Loaded} transfers responsibility of releasing the 
	 *   given {@link DomainObject} to this {@link Loaded}'s {@link #close()} method. 
	 */
	public Loaded(T domainObject, String name, FSRL fsrl, Project project, String projectRootPath,
			boolean mirrorFsLayout, Object consumer) {
		this.domainObject = domainObject;
		this.name = name;
		this.fsrl = fsrl;
		this.project = project;
		this.mirrorFsLayout = mirrorFsLayout;
		this.loadedConsumer = consumer;
		setProjectFolderPath(projectRootPath);
	}

	/**
	 * Creates a new {@link Loaded} object.
	 * <p>
	 * This object needs to be {@link #close() closed} when done with it.
	 * 
	 * @param domainObject The loaded {@link DomainObject}
	 * @param settings The {@link Loader.ImporterSettings}.
	 */
	public Loaded(T domainObject, ImporterSettings settings) {
		this(domainObject, settings.importName(), settings.provider().getFSRL(), settings.project(),
			settings.projectRootPath(), settings.mirrorFsLayout(), settings.consumer());
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
		return projectRootPath;
	}

	/**
	 * Sets the project folder path this will get saved to during a {@link #save(TaskMonitor)} 
	 * operation.
	 * 
	 * @param projectRootPath The project folder path that all {@link Loaded} {@link DomainObject}s
	 *   will be saved relative to. If {@code null}, "/" will be used.
	 */
	public void setProjectFolderPath(String projectRootPath) {
		if (projectRootPath == null || projectRootPath.isBlank()) {
			projectRootPath = "/";
		}
		else if (!projectRootPath.endsWith("/")) {
			projectRootPath += "/";
		}

		this.projectRootPath =
			mirrorFsLayout ? FSUtilities.mirroredProjectPath(projectRootPath) : projectRootPath;
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
	 * @throws IOException If there was an IO-related error, a project wasn't specified, an invalid
	 *   name was specified, or it was already successfully saved and still exists
	 * @throws InvalidNameException if saving with an invalid name
	 */
	public DomainFile save(TaskMonitor monitor)
			throws CancelledException, ClosedException, IOException, InvalidNameException {

		if (project == null) {
			throw new IOException("Cannot save to null project");
		}

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

		if (mirrorFsLayout && fsrl != null) {
			domainFile = mirror(monitor);
			return domainFile;
		}

		int uniqueNameIndex = 0;
		String uniqueName = FilenameUtils.getName(name);
		DomainFolder programFolder =
			ProjectDataUtils.createDomainFolderPath(project.getProjectData().getRootFolder(),
				FSUtilities.appendPath(projectRootPath, FilenameUtils.getFullPath(name)));
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

	/**
	 * A project link and its associated metadata that was created during the mirror process
	 * 
	 * @param linkFile The {@link DomainFile project link}. It may link to a {@link DomainFile} or
	 *   a {@link DomainFolder}.
	 * @param projectLinkTarget The project path of the link's target
	 * @param symlink The original target value of the link. It may be either relative, or absolute.
	 * @param relative True if the {@code symlink} is relative; false if it is absolute
	 */
	private record MirroredLink(DomainFile linkFile, String projectLinkTarget, String symlink,
			boolean relative) {}

	/**
	 * Saves the loaded {@link DomainObject} to the given {@link Project}, mirroring this object's 
	 * filesystem path in the project. Depending on the nature of the filesystem path, project
	 * folder and/or file links may be created during the save.
	 * 
	 * @param monitor A cancelable task monitor
	 * @return The {@link DomainFile} where the save happened
	 * @throws CancelledException if the operation was cancelled
	 * @throws IOException If there was an IO-related error
	 * @throws InvalidNameException if saving with an invalid name
	 */
	private DomainFile mirror(TaskMonitor monitor)
			throws IOException, InvalidNameException, CancelledException {
		DomainFolder mirrorRootProjectFolder = ProjectDataUtils
				.createDomainFolderPath(project.getProjectData().getRootFolder(), projectRootPath);
		String currentPath = null;
		Set<String> processedPaths = new HashSet<>();
		String[] pathElements = FSUtilities.splitPath(fsrl.getPath());
		try (RefdFile ref = FileSystemService.getInstance().getRefdFile(fsrl, monitor)) {
			for (int i = 0; i < pathElements.length; i++) {
				String pathElement = pathElements[i];
				if (i == 0) {
					if (!pathElement.isEmpty()) {
						throw new IOException("FSRL '%s' is not absolute!".formatted(fsrl));
					}
					currentPath = "/";
					continue;
				}
				currentPath = FSUtilities.appendPath(currentPath, pathElement);
				if (processedPaths.contains(currentPath)) {
					continue;
				}
				GFileSystem fs = ref.fsRef.getFilesystem();
				GFile currentFile = fs.lookup(currentPath);
				String currentParentDirPath = currentFile.getParentFile().getPath();
				DomainFolder parentProjectFolder = ProjectDataUtils.getDomainFolder(
					mirrorRootProjectFolder, FSUtilities.mirroredProjectPath(currentParentDirPath));
				FileAttributes fattrs = fs.getFileAttributes(currentFile, monitor);
				String symlinkDest = fattrs.get(SYMLINK_DEST_ATTR, String.class, null);
				if (symlinkDest != null) {
					MirroredLink mirroredLink =
						mirrorLinkInProject(currentFile, symlinkDest, parentProjectFolder, monitor);
					String symlink = mirroredLink.relative()
							? FSUtilities.appendPath(currentParentDirPath, mirroredLink.symlink())
							: mirroredLink.symlink();
					symlink = Path.of(symlink).normalize().toString(); // fixup any '.' and '..'
					String[] oldElements = pathElements;
					String[] newElements = FSUtilities.splitPath(symlink);
					pathElements =
						Arrays.copyOf(newElements, newElements.length + oldElements.length - i - 1);
					System.arraycopy(oldElements, i + 1, pathElements, newElements.length,
						pathElements.length - newElements.length);
					i = -1;
				}
				else if (currentFile.isDirectory()) {
					ProjectDataUtils.createDomainFolderPath(mirrorRootProjectFolder,
						FSUtilities.mirroredProjectPath(currentPath));
					processedPaths.add((currentPath));
				}
				else {
					try {
						if (domainObject instanceof Program program) {
							program.withTransaction("Updating Program Info", () -> {
								program.setExecutablePath(FSUtilities.appendPath(
									parentProjectFolder.getPathname(), currentFile.getName()));
								FSRL.writeToProgramInfo(program, currentFile.getFSRL());
							});
						}
						return parentProjectFolder.createFile(currentFile.getName(), domainObject,
							monitor);
					}
					catch (DuplicateFileException e) {
						DomainFile f = parentProjectFolder.getFile(currentFile.getName());
						Msg.warn(this, "Skipping save of existing file: " + f);
						return f;
					}
				}
			}
			throw new IOException("Path did not point to a file!");
		}
	}

	/**
	 * Creates a file or folder link in the project
	 * 
	 * @param file The {@link GFile link file}
	 * @param linkDest The link destination (relative or absolute)
	 * @param folder The {@link DomainFolder} to create the link in
	 * @param monitor A cancelable task monitor
	 * @return The newly created {@link MirroredLink project link}
	 * @throws IOException if an IO-related error occurred
	 */
	private MirroredLink mirrorLinkInProject(GFile file, String linkDest, DomainFolder folder,
			TaskMonitor monitor) throws IOException {
		boolean relative = FilenameUtils.getPrefixLength(linkDest) == 0;
		String projectLinkTarget = FSUtilities.mirroredProjectPath(relative
				? FSUtilities.appendPath(projectRootPath,
					FilenameUtils.getFullPath(file.getPath()), linkDest)
				: FSUtilities.appendPath(projectRootPath, linkDest));
		DomainFile df = folder.getFile(file.getName());
		if (df == null) {
			df = folder.createLinkFile(project.getProjectData(), projectLinkTarget, relative,
				file.getName(), file.isDirectory() ? FolderLinkContentHandler.INSTANCE
						: ProgramLinkContentHandler.INSTANCE);
		}
		return new MirroredLink(df, projectLinkTarget, linkDest, relative);
	}
}
