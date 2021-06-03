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
 * Defines methods for accessing a workspace; a workspace is
 * simply a group of running tools and their templates.
 */
public interface Workspace {

	/**
	 * Get the workspace name
	 * @return the name
	 */
	public String getName();

	/**
	 * Get the running tools in the workspace.
	 * 
	 * @return list of running tools or zero-length array if there are no tools in the workspace
	 */
	public PluginTool[] getTools();

	/**
	 * Launch an empty tool.
	 * @return name of empty tool that is launched.
	 */
	public PluginTool createTool();

	/**
	 * Run the tool specified by the tool template object.
	 * @param template the template
	 * @return launched tool that is now running.
	 */
	public PluginTool runTool(ToolTemplate template);

	/**
	 * Rename this workspace.
	 * 
	 * @param newName new workspace name
	 * 
	 * @throws DuplicateNameException if newName is already the
	 * name of a workspace.
	 */
	public void setName(String newName)
			throws DuplicateNameException;

	/**
	 * Set this workspace to be the active workspace, i.e.,
	 * all tools become visible.
	 * The currently active workspace becomes inactive, and
	 * this workspace becomes active.
	 */
	public void setActive();

}
