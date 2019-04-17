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
package ghidra.util.table;

import javax.swing.JTable;

import ghidra.framework.plugintool.Plugin;

/**
 * This action is used by {@link GhidraTable}s to allow the user to trigger navigation when 
 * selections are made.
 * <p>
 * This class will save the state of the action when the tool is saved.
 * 
 * @see AbstractSelectionNavigationAction
 */
public class SelectionNavigationAction extends AbstractSelectionNavigationAction {

	private static final String ACTION_NAME = "Selection Navigation Action";

	/**
	 * Constructor that relies on an instance of {@link GhidraTable} to do the work of
	 * navigation.  Clients that have {@link JTable}s that are not instances of {@link GhidraTable}
	 * can use the super class action and define its {@link #navigate()} callback method.
	 * 
	 * @param plugin The owner plugin
	 * @param table The {@link GhidraTable} which this action works with
	 * @see AbstractSelectionNavigationAction
	 */
	public SelectionNavigationAction(Plugin plugin, GhidraTable table) {
		this(plugin.getName(), table);
	}

	/**
	 * Constructor that relies on an instance of {@link GhidraTable} to do the work of
	 * navigation.  Clients that have {@link JTable}s that are not instances of {@link GhidraTable}
	 * can use the super class action and define its {@link #navigate()} callback method.
	 * 
	 * @param owner The owner name
	 * @param table The {@link GhidraTable} which this action works with
	 * @see AbstractSelectionNavigationAction
	 */
	public SelectionNavigationAction(String owner, GhidraTable table) {
		super(ACTION_NAME, owner, table);
	}

	@Override
	// overridden to tell the GhidraTable when it is allowed to navigate
	protected void toggleSelectionListening(boolean listen) {
		if (table == null) {
			return; // during our parent's initialization
		}

		// we know it's a GhidraTable due to our constructor, which forces that constraint
		((GhidraTable) table).setNavigateOnSelectionEnabled(listen);
		saveState();
	}

	@Override
	public void navigate() {
		// we do nothing, since we use a GhidraTable and it will navigate for us
	}
}
