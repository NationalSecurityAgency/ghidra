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
package ghidra.plugins.fsbrowser;

import java.util.List;

import docking.action.DockingAction;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * Extension point, used by the {@link FSBComponentProvider} to create actions that appear
 * in the fsb tree, and to delegate focus and default actions.
 */
public interface FSBFileHandler extends ExtensionPoint {
	/**
	 * Called once after creation of each instance to provide useful info
	 * 
	 * @param context references to useful objects and services
	 */
	void init(FSBFileHandlerContext context);

	/**
	 * Returns a list of {@link DockingAction}s that should be 
	 * {@link PluginTool#addLocalAction(docking.ComponentProvider, docking.action.DockingActionIf) added}
	 * to the {@link FSBComponentProvider} tree as local actions.
	 * 
	 * @return list of {@link DockingAction}s
	 */
	default List<DockingAction> createActions() {
		return List.of();
	}

	/**
	 * Called when a file node is focused in the {@link FSBComponentProvider} tree.
	 * 
	 * @param fileNode {@link FSBFileNode} that was focused
	 * @return boolean true if action was taken
	 */
	default boolean fileFocused(FSBFileNode fileNode) {
		return false;
	}

	/**
	 * Called when a file node is the target of a 'default action' initiated by the user, such
	 * as a double click, etc.
	 * 
	 * @param fileNode {@link FSBFileNode} that was acted upon
	 * @return boolean true if action was taken, false if no action was taken
	 */
	default boolean fileDefaultAction(FSBFileNode fileNode) {
		return false;
	}

	/**
	 * Returns a list of {@link DockingAction}s that should be added to a popup menu.  Called
	 * each time a fsb browser tree popup menu is created.
	 * <p>
	 * Only use this method to provide actions when the actions need to be created freshly
	 * for each popup event.  Normal long-lived actions should be published by the
	 * {@link #createActions()} method.
	 * 
	 * @return list of {@link DockingAction}s
	 */
	default List<DockingAction> getPopupProviderActions() {
		return List.of();
	}
}
