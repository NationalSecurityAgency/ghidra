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
package ghidra.framework.model;

import java.io.IOException;
import java.net.URL;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.store.LockException;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.NotFoundException;

/**
 * Interface for methods to create, open, and delete projects; maintains a
 * list of known project views that the user opened. 
 * It has a handle to the currently opened project. A project can be
 * opened by one user at a time.
 *  
 */
public interface ProjectManager {

	public static final String APPLICATION_TOOL_EXTENSION = ".tcd";// default extension for tools
	public static final String APPLICATION_TOOLS_DIR_NAME = "tools";//tools directory name 

	/**
	 * Create a project on the local filesystem.
	 * 
	 * @param projectLocator location for where the project should be created
	 * @param repAdapter repository adapter if this project is to be a 
	 *        shared project; may be null if the project is not shared.
	 * @param remember if false the new project should not be remembered (i.e., recently opened, etc.)
	 * @return the new project
	 * @throws IOException if user cannot access/write the project location
	 */
	public Project createProject(ProjectLocator projectLocator, RepositoryAdapter repAdapter,
			boolean remember) throws IOException;

	/**
	 * Get list of projects that user most recently opened.
	 * @return list of project URLs 
	 */
	public ProjectLocator[] getRecentProjects();

	/**
	 * Get list of projects that user most recently viewed.
	 * @return list of project URLs 
	 */
	public URL[] getRecentViewedProjects();

	/**
	 * Get the project that is currently open.
	 * @return currently open project, return null if there is no
	 * project opened
	 */
	public Project getActiveProject();

	/**
	 * Get the last opened (active) project.
	 * @return project last opened by the user; returns NULL if a project
	 * was never opened OR the last opened project is no longer valid
	 */
	public ProjectLocator getLastOpenedProject();

	/**
	 * Set the projectLocator of last opened (active) project; this projectLocator is returned
	 * in the getLastOpenedProject() method.
	 * @param projectLocator project location of last project that was opened
	 */
	public void setLastOpenedProject(ProjectLocator projectLocator);

	/**
	 * Keep the projectLocator on the list of known projects.
	 * @param projectLocator project location
	 */
	public void rememberProject(ProjectLocator projectLocator);

	/**
	 * Keep the url on the list of known projects.
	 * @param url project identifier
	 */
	public void rememberViewedProject(URL url);

	/**
	 * Remove the project url from the list of known viewed projects.
	 * @param url project identifier
	 */
	public void forgetViewedProject(URL url);

	/**
	 * Open a project from the file system. Add the project url
	 * to the list of known projects.
	 * @param projectLocator project location
	 * @param doRestore true if the project should be restored
	 * @param resetOwner if true, the owner of the project will be changed to the current user.
	 * @return opened project
	 * @throws NotFoundException if the file for the project was
	 * not found.
	 * @throws NotOwnerException if the project owner is not the user
	 * @throws LockException if the project is already opened by another user
	 */
	public Project openProject(ProjectLocator projectLocator, boolean doRestore, boolean resetOwner)
			throws NotFoundException, NotOwnerException, LockException;

	/**
	 * Delete the project in the given location.
	 * 
	 * @param projectLocator project location
	 * @return false if no project was deleted.
	 */
	public boolean deleteProject(ProjectLocator projectLocator);

	/**
	 * Returns true if a project with the given projectLocator exists.
	 * @param projectLocator project location
	 */
	public boolean projectExists(ProjectLocator projectLocator);

	/**
	 * Establish a connection to the given host and port number. 
	 * @param host server name or IP address
	 * @param portNumber server port or 0 for default
	 * @param forceConnect if true and currently not connected, an attempt will be be to connect
	 * @return a handle to the remote server containing shared repositories
	 */
	public RepositoryServerAdapter getRepositoryServerAdapter(String host, int portNumber,
			boolean forceConnect);

	/**
	 * Get the information that was last used to access a repository
	 * managed by a Ghidra server.
	 */
	public ServerInfo getMostRecentServerInfo();

	/**
	 * Return the user's ToolChest
	 */
	public ToolChest getUserToolChest();

}
