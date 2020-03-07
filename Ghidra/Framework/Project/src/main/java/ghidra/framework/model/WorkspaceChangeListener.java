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

import java.beans.PropertyChangeListener;

import ghidra.framework.plugintool.PluginTool;

/**
 * Listener that is notified when a tool is added or removed from a 
 * workspace, or when workspace properties change.
 */
public interface WorkspaceChangeListener extends PropertyChangeListener {

	/**
	 * Notification that a tool was added to the given workspace.
	 * @param ws workspace the affected workspace
	 * @param tool tool that was added
	 */
	public void toolAdded(Workspace ws, PluginTool tool);

	/**
	 * Notification that a tool was removed from the given workspace.
	 * @param ws workspace the affected workspace
	 * @param tool tool that was removed from the workspace
	 */
	public void toolRemoved(Workspace ws, PluginTool tool);

	/**
	 * Notification that the given workspace was added by the ToolManager.
	 * @param ws workspace the affected workspace
	 */
	public void workspaceAdded(Workspace ws);

	/**
	 * Notification that the given workspace was removed by the ToolManager.
	 * @param ws workspace the affected workspace
	 */
	public void workspaceRemoved(Workspace ws);

	/**
	 * Notification that the given workspace is the current one.
	 * @param ws workspace the affected workspace
	 */
	public void workspaceSetActive(Workspace ws);
}
