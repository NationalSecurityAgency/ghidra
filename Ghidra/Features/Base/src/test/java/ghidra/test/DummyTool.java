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
package ghidra.test;

import java.awt.Window;
import java.beans.PropertyChangeListener;
import java.beans.PropertyVetoException;
import java.util.Collections;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.event.ChangeListener;

import org.jdom.Element;

import docking.*;
import docking.action.DockingActionIf;
import ghidra.framework.model.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.project.tool.ToolIconURL;
import ghidra.program.model.listing.Program;

public class DummyTool implements Tool {
	private final static String DEFAULT_NAME = "untitled";
	private String name = DEFAULT_NAME;
	private String instanceName;
	private String description;
	private ToolIconURL iconURL;
	private Project project;

	public DummyTool() {
		this(DEFAULT_NAME);
	}

	public DummyTool(String name) {
		this.name = name;
		instanceName = "";
	}

	public DummyTool(Project project) {
		this.project = project;
	}

	/**
	 * Sets the type name of the tool.
	 * @exception PropertyVetoException thrown if a VetoableChangeListener
	 * rejects the change
	 */
	@Override
	public void setToolName(String typeName) throws PropertyVetoException {
		name = typeName;
	}

	/**
	 * Tells the tool to stop functioning and release its resources.
	 * Called by Session when it wants to dispose of a tool.  The tool
	 * MUST NOT call System.exit() in response to this method call.  Instead
	 * the tool should dispose of all its windows and other resources.
	 */
	@Override
	public void exit() {
		//do nothing
	}

	/* (non-Javadoc)
	 * @see ghidra.framework.model.Tool#close()
	 */
	@Override
	public void close() {
		if (project != null) {
			project.getToolServices().closeTool(this);
		}

	}

	@Override
	public boolean canCloseDomainFile(DomainFile domainFile) {
		return true;
	}

	/**
	 * Associates a unique(within a session) name to a tool instance.
	 */
	@Override
	public void putInstanceName(String newInstanceName) {
		this.instanceName = newInstanceName;
	}

	/**
	 * Returns the name associated with the tool's type.
	 */
	@Override
	public String getToolName() {
		return name;
	}

	/**
	 * Sets the tool visible or invisible.  This method is used by
	 * the Session to make it's tools visible or invisible depending
	 * on whether or not the session this tool is in is the current Session.
	 *
	 * @param visibility true specifies that the tool should be visible.
	 */
	@Override
	public void setVisible(boolean visibility) {
		//do nothing
	}

	/**
	 * @see ghidra.framework.model.Tool#isVisible()
	 */
	@Override
	public boolean isVisible() {
		return false;
	}

	@Override
	public void toFront() {
		//do nothing
	}

	/**
	 * returns a combination of the type name and the instance name of the
	 * form typename(instancename)
	 */
	@Override
	public String getName() {
		return name + instanceName;
	}

	/**
	 * Returns a list of eventNames that this Tool is interested in.
	 */
	@Override
	public String[] getConsumedToolEventNames() {
		return new String[] { "DummyToolEvent" };
	}

	/**
	 * Returns the tool's unique name.
	 */
	@Override
	public String getInstanceName() {
		return instanceName;
	}

	/**
	 * Adds a ToolListener to be notified only for a specific ToolEvent.
	 *
	 * @param listener The ToolListener to be added.
	 * @param toolEvent The name of the desired event.
	 */
	public void addToolListener(ToolListener listener, String toolEvent) {
		//do nothing
	}

	/**
	 * Adds a ToolListener to be notified only for a specific ToolEvent.
	 *
	 * @param listener The ToolListener to be added.
	 * @param toolEvent The name of the desired event.
	 */
	@Override
	public void addToolListener(ToolListener listener) {
		//do nothing
	}

	/**
	 * Returns the names of all the possible ToolEvents that this
	 * tool might generate.  Used by the ConnectionManager to connect
	 * tools together.
	 */
	@Override
	public String[] getToolEventNames() {
		return new String[] { "DummyToolEvent" };
	}

	/**
	 * Removes a ToolListener from receiving the specific event.
	 *
	 * @param listener The ToolListener to be removed.
	 * @param toolEvent The name of the event that no longer is of interest.
	 */
	public void removeToolListener(ToolListener listener, String toolEvent) {
		//do nothing
	}

	/**
	 * Removes a ToolListener from receiving the specific event.
	 *
	 * @param listener The ToolListener to be removed.
	 * @param toolEvent The name of the event that no longer is of interest.
	 */
	@Override
	public void removeToolListener(ToolListener listener) {
		//do nothing
	}

	/**
	 * Check whether this tool has changed its configuration.
	 * This is called to check if a tool needs to save its state, when the
	 * tool exits or the session the tool is in closes.
	 *
	 * @return true if the tool's configuration has changed, false otherwise
	 */
	@Override
	public boolean hasConfigChanged() {
		return false;
	}

	/**
	 * Add a change listener that is notified when a tool changes its state.
	 */
	public void addChangeListener(ChangeListener l) {
		//do nothing
	}

	/**
	 * Add property change listener.
	 */
	@Override
	public void addPropertyChangeListener(PropertyChangeListener l) {
		//do nothing
	}

	/**
	 * Get the classes of the data types that this tool supports,
	 * i.e., what data types can be dropped onto this tool.
	 */
	@Override
	public Class<?>[] getSupportedDataTypes() {
		return new Class[] { Program.class };
	}

	/**
	 * When the user drags a data file onto a tool, an event will be fired
	 * that the tool will respond to by accepting the data.
	 *
	 * @param data the data to be used by the running tool
	 */
	@Override
	public boolean acceptDomainFiles(DomainFile[] data) {
		return true;
	}

	/**
	 * Get the domain files that this tool currently has open.
	 */
	@Override
	public DomainFile[] getDomainFiles() {
		return null;
	}

	/**
	 * Remove the change listener.
	 */
	public void removeChangeListener(ChangeListener l) {
		//do nothing
	}

	/**
	 * Tells tool to write its config state from the given output stream.
	 */
	@Override
	public void setConfigChanged(boolean changed) {
		//do nothing
	}

	/**
	 * Tells tool to write its config state from the given output stream.
	 */
	@Override
	public Element saveToXml(boolean includeConfigState) {
		return null;
	}

	/**
	 * Tells tool to write its config state from the given output stream.
	 */
	@Override
	public Element saveDataStateToXml(boolean isTransactionState) {
		return null;
	}

	/**
	 * Tells tool to write its config state from the given output stream.
	 */
	public void restoreFromXml(Element root) {
		//do nothing
	}

	/**
	 * Tells tool to write its config state from the given output stream.
	 */
	@Override
	public void restoreDataStateFromXml(Element root) {
		//do nothing
	}

	/**
	 * Remove property change listener.
	 */
	@Override
	public void removePropertyChangeListener(PropertyChangeListener l) {
		//do nothing
	}

	/**
	 * This method is invoked when the registered ToolEvent event occurs.
	 *
	 * @param toolEvent The ToolEvent.
	 */
	@Override
	public void processToolEvent(PluginEvent toolEvent) {
		//do nothing
	}

	/**
	 * Fire the plugin event by notifying the event manager which
	 * calls the listeners.
	 */
	@Override
	public void firePluginEvent(PluginEvent event) {
		//do nothing
	}

	/**
	 * Get the description of the tool.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Set the description of the tool.
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * Set the icon for this tool configuration.
	 */
	@Override
	public void setIconURL(ToolIconURL iconURL) {
		this.iconURL = iconURL;
	}

	/**
	 * Get the icon for this tool configuration.
	 *
	 * @return Icon
	 */
	@Override
	public ToolIconURL getIconURL() {
		return iconURL;
	}

	@Override
	public ImageIcon getIcon() {
		return iconURL.getIcon();
	}

	@Override
	public ToolTemplate saveToolToToolTemplate() {
		return getToolTemplate(true);
	}

	/**
	 * @see ghidra.framework.model.Tool#enableClose()
	 */
	public void enableClose() {
		//do nothing
	}

	@Override
	public ToolTemplate getToolTemplate(boolean includeConfigState) {
		return new DummyToolTemplate();
	}

	@Override
	public void restoreWindowingDataFromXml(Element windowData) {
		//do nothing
	}

	@Override
	public Element saveWindowingDataToXml() {
		return null;
	}

	@Override
	public boolean shouldSave() {
		return false;
	}

	@Override
	public boolean canClose(boolean isExiting) {
		return true;
	}

	@Override
	public void addComponentProvider(ComponentProvider componentProvider, boolean show) {
		//do nothing
	}

	@Override
	public void removeComponentProvider(ComponentProvider componentProvider) {
		//do nothing
	}

	@Override
	public ComponentProvider getComponentProvider(String providerName) {
		return null;
	}

	@Override
	public void addLocalAction(ComponentProvider componentProvider, DockingActionIf action) {
		//do nothing
	}

	@Override
	public void removeLocalAction(ComponentProvider componentProvider, DockingActionIf action) {
		//do nothing
	}

	@Override
	public List<DockingActionIf> getAllActions() {
		return Collections.emptyList();
	}

	@Override
	public List<DockingActionIf> getDockingActionsByOwnerName(String owner) {
		return Collections.emptyList();
	}

	@Override
	public List<DockingActionIf> getDockingActionsByFullActionName(String fullActionName) {
		return Collections.emptyList();
	}

	@Override
	public void showComponentProvider(ComponentProvider componentProvider, boolean visible) {
		//do nothing
	}

	@Override
	public void showDialog(DialogComponentProvider dialogComponent) {
		// do nothing
	}

	@Override
	public void toFront(ComponentProvider componentProvider) {
		//do nothing
	}

	@Override
	public DockingWindowManager getWindowManager() {
		return null;
	}

	@Override
	public boolean isVisible(ComponentProvider componentProvider) {
		return true;
	}

	@Override
	public boolean isActive(ComponentProvider componentProvider) {
		return false;
	}

	@Override
	public void updateTitle(ComponentProvider componentProvider) {
		//do nothing
	}

	@Override
	public void contextChanged(ComponentProvider provider) {
		//do nothing
	}

	@Override
	public void setStatusInfo(String text) {
		//do nothing
	}

	@Override
	public void addAction(DockingActionIf action) {
		//do nothing
	}

	@Override
	public void removeAction(DockingActionIf action) {
		//do nothing
	}

	@Override
	public Window getProviderWindow(ComponentProvider componentProvider) {
		return null;
	}

	@Override
	public ToolOptions getOptions(String categoryName) {
		return null;
	}
}
