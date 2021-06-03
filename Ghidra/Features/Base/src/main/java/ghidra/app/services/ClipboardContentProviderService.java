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
package ghidra.app.services;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.util.List;

import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.ComponentProvider;
import ghidra.app.util.ClipboardType;
import ghidra.util.task.TaskMonitor;

/**
 * Determines what types of transfer data can be placed on the clipboard, as well as if 
 * cut, copy, and paste operations are supported
 */
public interface ClipboardContentProviderService {

	/**
	 * Returns the component provider associated with this service
	 * @return the provider
	 */
	public ComponentProvider getComponentProvider();

	/**
	 * Triggers the default copy operation
	 * @param monitor monitor that shows progress of the copy to clipboard, and
	 * may be canceled
	 * @return the created transferable; null if the copy was unsuccessful
	 */
	public Transferable copy(TaskMonitor monitor);

	/**
	 * Triggers a special copy with the specified copy type.
	 * @param copyType contains the data flavor of the clipboard contents
	 * @param monitor monitor that shows progress of the copy to clipboard, and
	 * may be canceled
	 * @return the created transferable; null if the copy was unsuccessful
	 */
	public Transferable copySpecial(ClipboardType copyType, TaskMonitor monitor);

	/**
	 * Triggers the default paste operation for the given transferable
	 * @param pasteData the paste transferable
	 * @return true of the paste was successful
	 */
	public boolean paste(Transferable pasteData);

	/**
	 * Gets the currently active ClipboardTypes for copying with the current context
	 * @return the types
	 */
	public List<ClipboardType> getCurrentCopyTypes();

	/**
	 * Return whether the given context is valid for actions on popup menus.
	 * @param context the context of where the popup menu will be positioned.
	 * @return true if valid
	 */
	public boolean isValidContext(ActionContext context);

	/**
	 * Returns true if copy should be enabled; false if it should be disabled.  This method can
	 * be used in conjunction with {@link #copy(TaskMonitor)} in order to add menu items to
	 * popup menus but to have them enabled when appropriate.
	 * @return true if copy should be enabled
	 */
	public boolean enableCopy();

	/**
	 * Returns true if copySpecial actions should be enabled;
	 * @return true if copySpecial actions should be enabled;
	 */
	public boolean enableCopySpecial();

	/**
	 * Returns true if paste should be enabled; false if it should be disabled.  This method can
	 * be used in conjunction with {@link #paste(Transferable)} in order to add menu items to
	 * popup menus but to have them enabled when appropriate.
	 * @return true if paste should be enabled
	 */
	public boolean enablePaste();

	/**
	 * Notification that the clipboard owner has lost its ownership.
	 * @param transferable the contents which the owner had placed on the clipboard
	 */
	public void lostOwnership(Transferable transferable);

	/**
	 * Adds a change listener that will be notified when the state of the service provider changes
	 * such that the ability to perform some actions has changed.  For example, the given
	 * listener will be called when a copy action can be performed when it was previously not
	 * possible. 
	 * 
	 * @param listener The listener to add.
	 */
	public void addChangeListener(ChangeListener listener);

	/**
	 * Removes the given change listener.
	 * @param listener The listener to remove.
	 * @see #addChangeListener(ChangeListener)
	 */
	public void removeChangeListener(ChangeListener listener);

	/**
	 * Returns true if the service can perform a paste operation using the given transferable.
	 * 
	 * @param availableFlavors data flavors available for the current clipboard transferable
	 * @return true if the service can perform a paste operation using the given transferable.
	 */
	public boolean canPaste(DataFlavor[] availableFlavors);

	/**
	 * Returns true if the given service provider can currently perform a copy operation.
	 * @return true if the given service provider can currently perform a copy operation.
	 */
	public boolean canCopy();

	/**
	 * Returns true if the given service provider can currently perform a 'copy special' 
	 * operation.
	 * @return true if copy special is enabled
	 */
	public boolean canCopySpecial();
}
