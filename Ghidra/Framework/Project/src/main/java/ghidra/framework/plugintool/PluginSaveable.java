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
package ghidra.framework.plugintool;

import java.util.*;

import javax.swing.Icon;

import ghidra.framework.model.DomainObject;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

/**
 * An item plugins can provide that allows the tool to prompt the user to save items generically.
 */
public abstract class PluginSaveable {

	/**
	 * {@return a string used to group  like items together}
	 */
	public abstract String getType();

	/**
	 * {@return an optional icon that will be shown to the user in the prompt to save}
	 */
	public Icon getIcon() {
		return Icons.EMPTY_ICON;
	}

	/**
	 * {@return the description of this saveable that will be shown to the user in the prompt to
	 * save}
	 */
	public abstract String getDescription();

	/**
	 * {@return tool tip text for this saveable or null}
	 */
	public String getToolTipText() {
		return null;
	}

	/**
	 * {@return true if this saveable is read-only}
	 * <P>
	 * Clients may wish to create saveables for read-only objects so that they are shown to the user
	 * at save time.
	 */
	public boolean isReadOnly() {
		return false;
	}

	/**
	 * Called to save this saveable.
	 * <p>
	 * Note: it is up to the client to notify the user if this method returns false when this 
	 * saveable cannot be saved.
	 * 
	 * @param monitor the task monitor
	 * @return true if the save was successful; false if save could not be completed
	 * @throws CancelledException if cancelled
	 */
	public abstract boolean save(TaskMonitor monitor) throws CancelledException;

	/**
	 * Returns the domain object that will be changed when this saveable is saved.
	 * <P>
	 * This method relates to {@link #getDomainObject()} in that either this method or that method 
	 * may return non-null, but not both,  as a saveable either uses a domain object directly or 
	 * will affect a dependent domain object indirectly when the saveable is saved. 
	 *  
	 * @return the affected domain object or null if saving this saveable does not affect any 
	 * domain object
	 */
	public DomainObject getDependent() {
		return null;
	}

	/**
	 * {@return the domain object used by this saveable, or null if this saveable does not directly
	 * use a domain object}
	 * <P>
	 * This method relates to {@link #getDependent()} in that either this method or that method may
	 * return non-null, but not both, as a saveable either uses a domain object directly or will 
	 * affect a dependent domain object indirectly when the saveable is saved. 
	 */
	public DomainObject getDomainObject() {
		return null;
	}

	@Override
	public String toString() {
		return getDescription();
	}

	/**
	 * A utility method that knows how to ask each tool for its saveables. This will also check the
	 * dependency of each saveable and include them, as they will change when the leaf saveable is
	 * changed.
	 * @param tools all tools to query
	 * @return the saveables
	 */
	public static List<PluginSaveable> getSaveablesFromAllTools(List<PluginTool> tools) {

		Set<PluginSaveable> allSaveables = new HashSet<>();
		for (PluginTool tool : tools) {
			Set<PluginSaveable> toolData = getSaveables(tool);
			allSaveables.addAll(toolData);
		}

		return new ArrayList<>(allSaveables);
	}

	private static Set<PluginSaveable> getSaveables(PluginTool tool) {
		Set<PluginSaveable> allSaveables = new HashSet<>();
		Set<PluginSaveable> saveables = tool.getUnsavedData();
		allSaveables.addAll(saveables);

		// get any domain objects that may be changed when we save each saveable
		for (PluginSaveable saveable : saveables) {
			DomainObject dobj = saveable.getDependent();
			if (dobj != null) {
				PluginSaveable depedentSaveable = tool.getSaveable(dobj);
				if (depedentSaveable != null) {
					allSaveables.add(depedentSaveable);
				}
			}
		}

		return allSaveables;
	}
}
