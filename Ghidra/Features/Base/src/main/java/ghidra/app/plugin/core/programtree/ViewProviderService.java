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
package ghidra.app.plugin.core.programtree;

import java.awt.event.MouseEvent;

import javax.swing.JComponent;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.services.ViewService;
import ghidra.framework.plugintool.ServiceInfo;

/**
 * Define methods for notification of which service becomes active;
 * the service is managed by the ViewManagerService.
 */
@ServiceInfo(description = "Provide a view that is managed by the ViewManagerService")
public interface ViewProviderService extends ViewService {

	/**
	 * Get the viewer component.
	 */
	public JComponent getViewComponent();

	/**
	 * Get the name of this view.
	 */
	public String getViewName();

	/**
	 * Set whether or not the component that is showing has focus.
	 * @param hasFocus true if the component has focus
	 */
	public void setHasFocus(boolean hasFocus);

	/**
	 * Return the object under the mouse location for the popup
	 * @param event mouse event generated when the right mouse button is pressed
	 */
	public Object getActivePopupObject(MouseEvent event);

	/**
	 * Returns the current action context for this view service
	 * @param event the mouse event
	 * @return the context
	 */
	public ActionContext getActionContext(MouseEvent event);

	/**
	 * Get the actions that would go on a tool bar.
	 */
	public DockingAction[] getToolBarActions();

	/**
	 * Notification that this view is closed.
	 * @return true if the view can be closed
	 */
	public boolean viewClosed();

	/**
	 * Notification that this view should be deleted
	 * @return true if the view can be deleted
	 */
	public boolean viewDeleted();

	/**
	 * Notification that this view should be renamed to newName.
	 * @return true if the rename is allowed
	 */
	public boolean viewRenamed(String newName);

	/**
	 * Returns the context for the current selection.
	 */
	public Object getActiveObject();

}
