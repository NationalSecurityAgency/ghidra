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

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.exception.DuplicateNameException;

/**
 * 
 * Interface to define methods to manage running tools and tools in
 * the Tool Chest. The ToolManager also keeps track of the workspaces, and
 * what tools are running in workspace, as well as the connections among tools
 * across all workspaces.
 * 
 * 
 */
public interface ToolManager {

	/**
	 * The name to use for a new unnamed workspace; used by the Ghidra
	 * Project Window when the user creates a new workspace.
	 */
	public final static String DEFAULT_WORKSPACE_NAME = "Workspace";

	/**
	 * Property used when sending the change event when a workspace name is
	 * changed.
	 */
	public final static String WORKSPACE_NAME_PROPERTY = "WorkspaceName";

	/**
	 * Get the connection object for the producer and consumer tools
	 * 
	 * @param producer tool that is producing the tool event
	 * @param consumer tool that is consuming the tool event
	 * @return the connection
	 */
	public ToolConnection getConnection(PluginTool producer, PluginTool consumer);

	/**
	 * Get a list of tools that produce at least one tool event.
	 * 
	 * @return zero-length array if no tool produces any events
	 */
	public PluginTool[] getProducerTools();

	/**
	 * Get a list of tools that consume at least one tool event.
	 * 
	 * @return zero-length array if no tool consumes any events
	 */
	public PluginTool[] getConsumerTools();

	/**
	 * Get a list running tools across all workspaces.
	 * 
	 * @return zero-length array if there are no running tools.
	 */
	public PluginTool[] getRunningTools();

	/**
	 * Create a workspace with the given name.
	 * 
	 * @param name name of workspace
	 * @return the workspace
	 * @throws DuplicateNameException if a workspace with this name already exists 
	 */
	public Workspace createWorkspace(String name) throws DuplicateNameException;

	/**
	 * Remove the workspace.
	 * 
	 * @param ws workspace to remove
	 */
	public void removeWorkspace(Workspace ws);

	/**
	 * Get list of known workspaces.
	 * 
	 * @return an array of known workspaces
	 */
	public Workspace[] getWorkspaces();

	/**
	 * Get the active workspace
	 * 
	 * @return the active workspace
	 */
	public Workspace getActiveWorkspace();

	/**
	 * Add the listener that will be notified when a tool is added
	 * or removed.
	 * 
	 * @param listener workspace listener to add
	 */
	public void addWorkspaceChangeListener(WorkspaceChangeListener listener);

	/**
	 * Remove the workspace listener.
	 * 
	 * @param l workspace listener to remove
	 */
	public void removeWorkspaceChangeListener(WorkspaceChangeListener l);

	/**
	 * Removes all connections involving tool
	 * @param tool tool for which to remove all connections
	 */
	public void disconnectTool(PluginTool tool);

	/**
	 * A configuration change was made to the tool; a plugin was added
	 * or removed.
	 * @param tool tool that changed
	 */
	public void toolChanged(PluginTool tool);
}
