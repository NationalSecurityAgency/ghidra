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
import java.util.*;

import javax.swing.*;
import javax.swing.event.ChangeListener;

import org.jdom.Element;

import docking.*;
import docking.action.DockingActionIf;
import docking.actions.DockingToolActions;
import docking.actions.PopupActionProvider;
import docking.util.image.ToolIconURL;
import ghidra.framework.model.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.*;
import ghidra.program.model.listing.Program;

public class DummyTool extends PluginTool {
	private final static String DEFAULT_NAME = "untitled";
	private String name = DEFAULT_NAME;
	private String instanceName;
	private String description;
	private ToolIconURL dummyIconUrl;
	private Project project;

	private DockingToolActions dummyToolActions = new DummyToolActions();

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

	@Override
	public void setToolName(String typeName) {
		name = typeName;
	}

	@Override
	public void exit() {
		//do nothing
	}

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

	@Override
	public void putInstanceName(String newInstanceName) {
		this.instanceName = newInstanceName;
	}

	@Override
	public String getToolName() {
		return name;
	}

	@Override
	public void setVisible(boolean visibility) {
		//do nothing
	}

	@Override
	public boolean isVisible() {
		return false;
	}

	@Override
	public void toFront() {
		//do nothing
	}

	@Override
	public String getName() {
		return name + instanceName;
	}

	@Override
	public String[] getConsumedToolEventNames() {
		return new String[] { "DummyToolEvent" };
	}

	@Override
	public String getInstanceName() {
		return instanceName;
	}

	public void addToolListener(ToolListener listener, String toolEvent) {
		//do nothing
	}

	@Override
	public void addToolListener(ToolListener listener) {
		//do nothing
	}

	@Override
	public String[] getToolEventNames() {
		return new String[] { "DummyToolEvent" };
	}

	public void removeToolListener(ToolListener listener, String toolEvent) {
		//do nothing
	}

	@Override
	public void removeToolListener(ToolListener listener) {
		//do nothing
	}

	@Override
	public boolean hasConfigChanged() {
		return false;
	}

	public void addChangeListener(ChangeListener l) {
		//do nothing
	}

	@Override
	public void addPropertyChangeListener(PropertyChangeListener l) {
		//do nothing
	}

	@Override
	public Class<?>[] getSupportedDataTypes() {
		return new Class[] { Program.class };
	}

	@Override
	public boolean acceptDomainFiles(DomainFile[] data) {
		return true;
	}

	@Override
	public DomainFile[] getDomainFiles() {
		return null;
	}

	public void removeChangeListener(ChangeListener l) {
		//do nothing
	}

	@Override
	public void setConfigChanged(boolean changed) {
		//do nothing
	}

	@Override
	public Element saveToXml(boolean includeConfigState) {
		return null;
	}

	@Override
	public Element saveDataStateToXml(boolean isTransactionState) {
		return null;
	}

	@Override
	public void restoreDataStateFromXml(Element root) {
		//do nothing
	}

	@Override
	public void removePropertyChangeListener(PropertyChangeListener l) {
		//do nothing
	}

	@Override
	public void processToolEvent(PluginEvent toolEvent) {
		//do nothing
	}

	@Override
	public void firePluginEvent(PluginEvent event) {
		//do nothing
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	@Override
	public void setIconURL(ToolIconURL iconUrl) {
		this.dummyIconUrl = iconUrl;
	}

	@Override
	public ToolIconURL getIconURL() {
		return dummyIconUrl;
	}

	@Override
	public ImageIcon getIcon() {
		return dummyIconUrl.getIcon();
	}

	@Override
	public ToolTemplate saveToolToToolTemplate() {
		return getToolTemplate(true);
	}

	public void enableClose() {
		//do nothing
	}

	@Override
	public ToolTemplate getToolTemplate(boolean includeConfigState) {
		return new DummyToolTemplate();
	}

	@Override
	public void restoreWindowingDataFromXml(Element element) {
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
	public void addPopupActionProvider(PopupActionProvider listener) {
		// do nothing
	}

	@Override
	public void removePopupActionProvider(PopupActionProvider listener) {
		// do nothing
	}

	@Override
	public Set<DockingActionIf> getAllActions() {
		return Collections.emptySet();
	}

	@Override
	public Set<DockingActionIf> getDockingActionsByOwnerName(String owner) {
		return Collections.emptySet();
	}

	@Override
	public ComponentProvider getActiveComponentProvider() {
		return null;
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
	public void setMenuGroup(String[] menuPath, String group, String menuSubGroup) {
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
	public void setStatusInfo(String text, boolean beep) {
		//do nothing
	}

	@Override
	public void clearStatusInfo() {
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

	@Override
	public void addContextListener(DockingContextListener listener) {
		//do nothing
	}

	@Override
	public void removeContextListener(DockingContextListener listener) {
		//do nothing		
	}

	@Override
	public DockingToolActions getToolActions() {
		return dummyToolActions;
	}

	@Override
	public <T> T getService(Class<T> serviceClass) {
		return null;
	}

	@Override
	public void addServiceListener(ServiceListener listener) {
		//do nothing		
	}

	@Override
	public void removeServiceListener(ServiceListener listener) {
		//do nothing		
	}

	@Override
	public PluginClassManager getPluginClassManager() {
		return null;
	}

	@Override
	public void addStatusComponent(JComponent c, boolean addBorder, boolean rightSide) {
		//do nothing
	}

	@Override
	public void removeStatusComponent(JComponent c) {
		//do nothing
	}

	@Override
	public JFrame getToolFrame() {
		return null;
	}

	@Override
	public UndoRedoToolState getUndoRedoToolState(DomainObject domainObject) {
		return new UndoRedoToolState(new ArrayList<>(), domainObject);
	}
}
