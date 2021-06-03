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
package ghidra.framework.data;

import ghidra.app.merge.MergeProgressModifier;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import javax.swing.JComponent;

/**
 * An interface to allow merging of domain objects.
 */
public interface DomainObjectMergeManager extends MergeProgressModifier {
	/**
	 * Merge domain objects and resolve any conflicts.
	 * @return true if the merge process completed successfully
	 * @throws CancelledException if the user canceled the merge process
	 */
	boolean merge(TaskMonitor monitor) throws CancelledException;
	
	/**
	 * Sets the resolve information object for the indicated standardized name.
	 * This is how information is passed between merge managers.
	 * @param infoType the string indicating the type of resolve information
	 * @param infoObject the object for the named string. This information is
	 * determined by the merge manager that creates it.
	 * @see ghidra.app.merge.MergeManager#getResolveInformation(String)
	 * MergeManager.getResolveInformation(String)
	 */
	public void setResolveInformation(String infoType, Object infoObject);
	
	/**
	 * Show the component that is used to resolve conflicts. This method
	 * is called by the MergeResolvers when user input is required. If the
	 * component is not null, this method blocks until the user either 
	 * cancels the merge process or resolves a conflict. If comp is null,
	 * then the default component is displayed, and the method does not
	 * wait for user input.
	 * @param comp component to show; if component is null, show the 
	 * default component and do not block
	 * @param componentID id or name for the component
	 */
	public void showComponent(final JComponent comp, final String componentID,
	        HelpLocation helpLoc);
	
	/**
	 * Enable the apply button according to the "enabled" parameter.
	 */
	public void setApplyEnabled(final boolean enabled);
	
	/**
	 * Clear the status text on the merge dialog.
	 *
	 */
	public void clearStatusText();
	
	/**
	 * Set the status text on the merge dialog.
	 */
	public void setStatusText(String msg);
	
}
