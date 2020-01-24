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
package ghidra.framework.project.tool;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;

import org.jdom.Element;

import docking.ComponentProvider;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateNameException;

/**
 * Tool manager that knows about all the running tools for each workspace
 * in the project; the tool manager is responsible for launching new tools,
 * and managing connections among tools.
 */
public class ToolManagerImpl implements ToolManager, PropertyChangeListener {

	private final static int TYPICAL_NUM_WORKSPACES = 3;
	private final static int TYPICAL_NUM_TOOLS = 5;
	private final static int TYPICAL_NUM_CONNECTIONS = 10;

	private enum ToolSaveStatus {
		AUTO_SAVE_MODE, ASK_SAVE_MODE,
	}

	private ToolChest toolChest;
	private ToolServicesImpl toolServices;

	private Map<Workspace, Workspace> changedWorkspaces;

	/** keep track of the workspaces in the project */
	private List<Workspace> workspaces;
	private Map<String, Workspace> wsMap; // map workspace name to workspace

	// map producer/consumer name to ToolConnection object
	private Map<String, ToolConnectionImpl> connectMap;

	// map generic tool names to list of tools
	private Map<String, List<PluginTool>> namesMap;

	/**
	 * keep a handle to the active workspace to make inactive when another
	 * workspace is made active
	 */
	private WorkspaceImpl activeWorkspace;
	private ArrayList<WorkspaceChangeListener> changeListeners;
	private boolean activeWorkspaceChanged;
	private boolean inRestoreMode;
	private Project project;

	private Map<String, ToolSaveStatus> toolStatusMap = new HashMap<>();

	public ToolManagerImpl(Project project) {
		this.project = project;
		this.toolChest = project.getLocalToolChest();
		toolServices = new ToolServicesImpl(toolChest, this);
		workspaces = new ArrayList<>(TYPICAL_NUM_WORKSPACES);
		changedWorkspaces = new HashMap<>(TYPICAL_NUM_WORKSPACES);
		connectMap = new HashMap<>(TYPICAL_NUM_CONNECTIONS);
		wsMap = new HashMap<>(TYPICAL_NUM_WORKSPACES);
		changeListeners = new ArrayList<>(3);
		namesMap = new HashMap<>(5);
		activeWorkspaceChanged = false;

	}

	/** 
	 * Registers the new instance of the tool in the namesMap and returns the total number of 
	 * running instances of that tool
	 * @param toolName the name of the tool being registers
	 * @param tool the tool being registered
	 */
	private void registerTool(String toolName, PluginTool tool) {
		List<PluginTool> list = namesMap.get(toolName);
		if (list == null) {
			list = new ArrayList<>(5);
			namesMap.put(toolName, list);
		}
		list.add(tool);

		if (list.size() == 1) {
			// first tool, set the default status
			toolStatusMap.put(toolName, ToolSaveStatus.AUTO_SAVE_MODE);
		}

		// make sure tools have unique name
		String instanceName = generateInstanceName(toolName, tool);
		tool.putInstanceName(instanceName);
		tool.addPropertyChangeListener(this);
	}

	private void deregisterTool(String toolName, PluginTool tool) {
		List<PluginTool> list = namesMap.get(toolName);
		SystemUtilities.assertTrue(list != null, "Attempted to remove tool that's not there");
		list.remove(tool);
		if (list.size() == 0) {
			namesMap.remove(toolName);
			toolStatusMap.remove(toolName);
		}
		tool.removePropertyChangeListener(this);
	}

	@Override
	public Workspace getActiveWorkspace() {
		return activeWorkspace;
	}

	@Override
	public PluginTool[] getConsumerTools() {
		ArrayList<PluginTool> consumers = new ArrayList<>(TYPICAL_NUM_TOOLS);
		PluginTool[] runningTools = getRunningTools();
		for (PluginTool tool : runningTools) {
			if (tool.getConsumedToolEventNames().length > 0) {
				consumers.add(tool);
			}
		}
		PluginTool[] tools = new PluginTool[consumers.size()];
		consumers.toArray(tools);
		return tools;
	}

	@Override
	public PluginTool[] getProducerTools() {
		ArrayList<PluginTool> producers = new ArrayList<>(TYPICAL_NUM_TOOLS);
		PluginTool[] runningTools = getRunningTools();
		for (PluginTool tool : runningTools) {
			if (tool.getToolEventNames().length > 0) {
				producers.add(tool);
			}
		}
		PluginTool[] tools = new PluginTool[producers.size()];
		return producers.toArray(tools);
	}

	@Override
	public PluginTool[] getRunningTools() {
		Workspace[] wsList = new Workspace[workspaces.size()];
		workspaces.toArray(wsList);
		ArrayList<PluginTool> runningTools = new ArrayList<>(TYPICAL_NUM_TOOLS);
		for (Workspace element : wsList) {
			PluginTool[] tools = element.getTools();
			for (PluginTool tool : tools) {
				runningTools.add(tool);
			}
		}

		PluginTool[] tools = new PluginTool[runningTools.size()];
		runningTools.toArray(tools);

		return tools;
	}

	/*
	 * @see ghidra.framework.model.ToolManager#getConnection(ghidra.framework.model.Tool, ghidra.framework.model.Tool)
	 */
	@Override
	public ToolConnection getConnection(PluginTool producer, PluginTool consumer) {
		String key = getKey(producer, consumer);
		ToolConnectionImpl tc = connectMap.get(key);
		if (tc == null) {
			tc = new ToolConnectionImpl(producer, consumer);
			connectMap.put(key, tc);
		}
		return tc;
	}

	@Override
	public Workspace createWorkspace(String name) throws DuplicateNameException {
		// if passed in the default "untitled" name, or no name at all,
		// then bump up the name with the "one-up" number to create a new one
		if (name == null || name.length() == 0) {
			name = DEFAULT_WORKSPACE_NAME;
		}
		if (isDefaultWorkspaceName(name)) {
			name = getUniqueWorkspaceName();
		}

		// duplicate workspaces are not allowed in the same project
		if (wsMap.containsKey(name)) {
			throw new DuplicateNameException("Duplicate workspace requested: " + name);
		}

		// create the new workspace and add it to the list of managed workspaces
		WorkspaceImpl ws = new WorkspaceImpl(name, this);
		workspaces.add(ws);
		wsMap.put(name, ws);

		// notify listeners of added workspace
		for (int i = 0; i < changeListeners.size(); i++) {
			WorkspaceChangeListener listener = changeListeners.get(i);
			listener.workspaceAdded(ws);
		}

		ws.setActive(); // calls ToolManagerImpl back to make the others inactive

		return ws;
	}

	/*
	 * @see ghidra.framework.model.ToolManager#removeWorkspace(ghidra.framework.model.Workspace)
	 */
	@Override
	public void removeWorkspace(Workspace ws) {
		// this is a programming error if it occurs
		if (!workspaces.contains(ws)) {
			Msg.showError(this, null, null, null,
				new RuntimeException("unknown/stale workspace reference: " + ws));
		}

		// first close all the tools running in the workspace
		// and if any of the tools don't close, don't remove the workspace
		PluginTool[] runningTools = ws.getTools();
		for (PluginTool runningTool : runningTools) {
			// if data has changed in the tool, the frontEnd will take care
			// of asking/confirming saving tool
			runningTool.close();
		}

		// if any of the tools didn't close, don't remove the workspace
		runningTools = ws.getTools();
		if (runningTools.length > 0) {
			return;
		}

		// remove workspace from list of workspaces
		String wsName = ws.getName();
		workspaces.remove(ws);
		wsMap.remove(wsName);

		// notify listeners of removed workspace
		for (int i = 0; i < changeListeners.size(); i++) {
			WorkspaceChangeListener listener = changeListeners.get(i);
			listener.workspaceRemoved(ws);
		}

		// set the oldest workspace to now be the active workspace;
		// if this is the last workspace, then create a new "empty"
		// workspace which is the project default
		if (workspaces.size() == 0) {
			try {
				createWorkspace(DEFAULT_WORKSPACE_NAME);
			}
			catch (DuplicateNameException e) {
				Msg.showError(this, null, "Duplicate Name",
					"Error Creating Default Workspace: " + e.getMessage());
			}
		}
		else {

			Workspace workspace = workspaces.get(0);
			workspace.setActive();
		}
	}

	@Override
	public Workspace[] getWorkspaces() {
		Workspace[] wsList = new Workspace[workspaces.size()];
		return workspaces.toArray(wsList);
	}

	/**
	 * Saves this object to an XML element
	 * @return the element containing the tool XML
	 */
	public Element saveToXml() {

		Element root = new Element("TOOL_MANAGER");
		root.setAttribute("ACTIVE_WORKSPACE", activeWorkspace.getName());
		for (int i = 0; i < workspaces.size(); i++) {
			WorkspaceImpl ws = (WorkspaceImpl) workspaces.get(i);
			root.addContent(ws.saveToXml());
		}
		Iterator<String> keys = connectMap.keySet().iterator();
		while (keys.hasNext()) {
			String key = keys.next();
			ToolConnectionImpl tc = connectMap.get(key);
			root.addContent(tc.saveToXml());
		}
		// reset the changed state back to "unchanged"
		changedWorkspaces.clear();
		activeWorkspaceChanged = false;
		return root;
	}

	/**
	 * restores the object from an XML element
	 * 
	 * @param root root element of saved XML state
	 */
	public void restoreFromXml(Element root) {
		inRestoreMode = true;
		try {
			HashMap<String, PluginTool> toolMap = new HashMap<>();
			String activeWSName = root.getAttributeValue("ACTIVE_WORKSPACE");

			Workspace makeMeActive = null;
			List<?> l = root.getChildren("WORKSPACE");
			Iterator<?> it = l.iterator();
			while (it.hasNext()) {
				Element elem = (Element) it.next();
				WorkspaceImpl ws = new WorkspaceImpl("TEMP", this);
				ws.restoreFromXml(elem);
				workspaces.add(ws);
				wsMap.put(ws.getName(), ws);
				if (ws.getName().equals(activeWSName)) {
					makeMeActive = ws;
				}
				PluginTool[] tools = ws.getTools();
				for (PluginTool tool : tools) {
					toolMap.put(tool.getName(), tool);
				}
			}
			if (makeMeActive != null) {
				makeMeActive.setActive();
			}

			it = root.getChildren("CONNECTION").iterator();
			while (it.hasNext()) {
				Element elem = (Element) it.next();
				String producerName = elem.getAttributeValue("PRODUCER");
				String consumerName = elem.getAttributeValue("CONSUMER");
				// get the tools
				PluginTool producer = toolMap.get(producerName);
				PluginTool consumer = toolMap.get(consumerName);
				if (producer != null && consumer != null) {
					ToolConnectionImpl tc = new ToolConnectionImpl(producer, consumer);
					tc.restoreFromXml(elem);
					connectMap.put(producerName + "+" + consumerName, tc);
				}
			}
		}
		finally {
			inRestoreMode = false;
		}
	}

	/**
	 * Return whether any tools have changed, or if any tools were
	 * added or removed from any of the workspaces.
	 * @return true if any tools in this workspace have changed
	 */
	public boolean hasChanged() {
		// check the connections for changes
		Iterator<String> keys = connectMap.keySet().iterator();
		while (keys.hasNext()) {
			String key = keys.next();
			ToolConnectionImpl tc = connectMap.get(key);
			if (tc.hasChanged()) {
				return true;
			}
		}

		// have the workspaces added/removed any tools?
		// or has the active workspace changed?
		return ((changedWorkspaces.size() > 0) || activeWorkspaceChanged);
	}

	/**
	 * Close all running tools in the project.
	 */
	public void close() {
		for (int i = 0; i < workspaces.size(); i++) {
			WorkspaceImpl w = (WorkspaceImpl) workspaces.get(i);
			w.close();
		}
	}

	/** 
	 * Save the tools that are opened and changed, that will be brought back up when the project
	 * is reopened
	 * @return true if the session was saved
	 */
	public boolean saveSessionTools() {
		Set<String> keySet = namesMap.keySet();
		for (String toolName : keySet) {
			List<PluginTool> tools = namesMap.get(toolName);
			if (tools.size() == 1) {
				PluginTool tool = tools.get(0);
				if (tool.shouldSave()) {
					toolServices.saveTool(tool);
				}
			}
			else {
				if (!saveToolSet(tools)) {
					return false;
				}
			}
		}

		return true;
	}

	private boolean saveToolSet(List<PluginTool> tools) {
		List<PluginTool> changedTools = new ArrayList<>();
		for (PluginTool tool : tools) {
			if (tool.hasConfigChanged()) {
				changedTools.add(tool);
			}
		}
		if (changedTools.isEmpty()) {
			return true;
		}

		if (changedTools.size() == 1) {
			PluginTool changedTool = changedTools.get(0);
			if (changedTool.shouldSave()) {
				toolServices.saveTool(changedTool);
			}
			return true; // we don't care if they save or not here; it is not a cancel
		}
		SelectChangedToolDialog dialog = new SelectChangedToolDialog(changedTools);
		FrontEndTool frontEndTool = AppInfo.getFrontEndTool();
		frontEndTool.showDialog(dialog, (ComponentProvider) null);

		if (dialog.wasCancelled()) {
			return false;
		}

		PluginTool tool = dialog.getSelectedTool();
		if (tool != null) {
			toolServices.saveTool(tool);
		}

		return true;
	}

	public void dispose() {
		toolServices.dispose();
	}

	/**
	 * Debug method for printing out the list of connections.
	 */
	public void dumpConnectionList() {
		Iterator<String> keys = connectMap.keySet().iterator();
		while (keys.hasNext()) {
			String key = keys.next();
			ToolConnection tc = connectMap.get(key);
			Msg.debug(this, key + "==> ");
			String[] events = tc.getEvents();
			for (String event : events) {
				Msg.debug(this, "\t isConnected for " + event + "? = " + tc.isConnected(event));
			}
		}
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {

		PluginTool tool = (PluginTool) evt.getSource();

		String propertyName = evt.getPropertyName();

		if (propertyName.equals(PluginTool.PLUGIN_COUNT_PROPERTY_NAME)) {
			updateConnections(evt);
		}

		if (!propertyName.equals(PluginTool.TOOL_NAME_PROPERTY)) {
			return;
		}

		String oldName = (String) evt.getOldValue();
		String newName = (String) evt.getNewValue();

		deregisterTool(oldName, tool);
		registerTool(newName, tool);

		// Update connectMap
		updateConnectMap(tool);

		// notify listeners of tool change
		firePropertyChangeEvent(evt);
	}

	@Override
	public void addWorkspaceChangeListener(WorkspaceChangeListener l) {
		changeListeners.add(l);
	}

	@Override
	public void removeWorkspaceChangeListener(WorkspaceChangeListener l) {
		changeListeners.remove(l);
	}

	////////////////////////////////////////////////////////////////////
	// not in the interface
	////////////////////////////////////////////////////////////////////
	/**
	 * Clear the flag so the user does not get prompted to save the
	 * project; flag gets set to true when a workspace is created, and
	 * a workspace is created when a new project is created.
	 */
	public void clearWorkspaceChanged() {
		activeWorkspaceChanged = false;
	}

	/**
	 * Get any tool services available from this tool
	 * 
	 * @return ToolServices list of tool services this tool can provide.
	 */
	public ToolServices getToolServices() {
		return toolServices;
	}

	@Override
	public void toolChanged(PluginTool tool) {
		updateConnectMap(tool);
	}

	/////////////////////////////////////////////////////////////
	// not in the interface -- needed by ProjectImpl when
	// restoring the front end tool.
	/**
	 * Called by WorkspaceImpl when it is restoring its state.
	 * @param toolName the name of the tool
	 * @return the tool
	 */
	public PluginTool getTool(String toolName) {
		ToolTemplate template = toolServices.getToolChest().getToolTemplate(toolName);
		if (template == null) {
			return null;
		}

		PluginTool tool = template.createTool(project);
		if (tool != null) {
			registerTool(toolName, tool);
		}
		return tool;
	}

	////////////////////////////////////////////////////////
	// ** package-level methods
	///////////////////////////////////////////////////////

	/**
	 *  Close a tool.
	 * 
	 * @param tool tool to be closed.
	 */
	void closeTool(PluginTool tool) {

		// find the workspace running the tool
		for (int i = 0; i < workspaces.size(); i++) {
			WorkspaceImpl ws = (WorkspaceImpl) workspaces.get(i);
			PluginTool[] tools = ws.getTools();
			for (PluginTool tool2 : tools) {
				if (tool == tool2) {
					ws.closeRunningTool(tool);
					return;
				}
			}
		}
	}

	/**
	 * Set the active workspace.
	 * 
	 * @param workspace workspace to set active
	 */
	void setActiveWorkspace(WorkspaceImpl workspace) {
		if (workspace == activeWorkspace) {
			return;
		}
		// if we're in the process of being restored, don't set the change flag
		if (!inRestoreMode) {
			activeWorkspaceChanged = true;
		}

		// set the current active workspace to inactive first, if there
		// is one. And since only one workspace can be active at a time,
		// we don't have to set each one in the list inactive
		if (activeWorkspace != null) {
			activeWorkspace.setVisible(false);
		}

		// remember the new one as the active one
		activeWorkspace = workspace;

		// notify listeners of new active workspace
		for (int i = 0; i < changeListeners.size(); i++) {
			WorkspaceChangeListener listener = changeListeners.get(i);
			listener.workspaceSetActive(activeWorkspace);
		}
	}

	/**
	 * Get a handle to the workspace with the given name.
	 * 
	 * @param name name of the workspace.
	 * 
	 * @return workspace handle if one exists.
	 */
	Workspace getWorkspace(String name) {
		return wsMap.get(name);
	}

	/**
	 * Mark workspace as changed.
	 * 
	 * @param ws workspace to tag
	 */
	void setWorkspaceChanged(WorkspaceImpl ws) {
		if (!changedWorkspaces.containsKey(ws)) {
			changedWorkspaces.put(ws, ws);
		}
	}

	/**
	 * Called by the workspace when it is updating its name;
	 * causes a property change event to be fired.
	 * 
	 * @param ws workspace to rename
	 * @param name new name of workspace
	 * 
	 * @throws DuplicateNameException if there already exists a workspace by the given name
	 */
	void setWorkspaceName(Workspace ws, String name) throws DuplicateNameException {

		if (wsMap.containsKey(name)) {
			throw new DuplicateNameException("Workspace named " + name + " already exists");
		}
		wsMap.remove(ws.getName());
		wsMap.put(name, ws);

		// fire property change event
		PropertyChangeEvent event =
			new PropertyChangeEvent(this, WORKSPACE_NAME_PROPERTY, ws.getName(), name);
		for (int i = 0; i < changeListeners.size(); i++) {
			WorkspaceChangeListener l = changeListeners.get(i);
			l.propertyChange(event);
		}
	}

	/*
	 * Get a tool from the template; set the instance name.
	 */
	PluginTool getTool(Workspace ws, ToolTemplate template) {
		PluginTool tool = template.createTool(project);
		if (tool != null) {
			registerTool(tool.getToolName(), tool);
		}
		return tool;
	}

	/*
	 * Called by the workspace when a tool is removed.
	 */
	void toolRemoved(Workspace ws, PluginTool tool) {
		deregisterTool(tool.getToolName(), tool);
		disconnectTool(tool);

		for (int i = 0; i < changeListeners.size(); i++) {
			WorkspaceChangeListener l = changeListeners.get(i);
			l.toolRemoved(ws, tool);
		}
	}

	/**
	 * Generate an instance name in the form
	 * of a one-up number.
	 */
	private String generateInstanceName(String toolName, PluginTool tool) {
		List<PluginTool> list = namesMap.get(toolName);
		if (list.size() <= 1) {
			return "";
		}

		PluginTool lastTool = list.get(list.size() - 2);	// the last one is the one we just added above
		String instanceName = lastTool.getInstanceName();
		if (instanceName.length() == 0) {
			return "2";
		}

		int n = Integer.parseInt(instanceName);
		return "" + (n + 1);
	}

	PluginTool createEmptyTool() {
		PluginTool tool = new GhidraTool(project, "Untitled");
		addNewTool(tool, "Untitled");
		return tool;
	}

	/**
	 * Add the tool to the table, add us as a listener for property
	 * changes on the tool.
	 */
	private void addNewTool(PluginTool tool, String toolName) {
		tool.setToolName(toolName);
		registerTool(toolName, tool);
	}

	void fireToolAddedEvent(Workspace ws, PluginTool tool) {
		for (int i = 0; i < changeListeners.size(); i++) {
			WorkspaceChangeListener l = changeListeners.get(i);
			l.toolAdded(ws, tool);
		}
	}

	@Override
	public void disconnectTool(PluginTool tool) {
		Iterator<String> keys = connectMap.keySet().iterator();
		while (keys.hasNext()) {
			String key = keys.next();
			ToolConnection tc = connectMap.get(key);
			PluginTool producer = tc.getProducer();
			PluginTool consumer = tc.getConsumer();
			if (producer == tool || consumer == tool) {
				keys.remove();
				producer.removeToolListener((ToolConnectionImpl) tc);
			}
		}
	}

	private void updateConnectMap(PluginTool tool) {
		Iterator<String> keys = connectMap.keySet().iterator();
		Map<String, ToolConnectionImpl> map = new HashMap<>();

		while (keys.hasNext()) {
			String key = keys.next();
			ToolConnectionImpl tc = connectMap.get(key);
			PluginTool producer = tc.getProducer();
			PluginTool consumer = tc.getConsumer();
			if (producer == tool || consumer == tool) {
				String newkey = getKey(producer, consumer);
				tc.updateEventList();
				map.put(newkey, tc);
			}
			else {
				map.put(key, tc);
			}
		}
		connectMap = map;
	}

	/**
	 * Get the key for the connection map.
	 * 
	 * @param producer tool producing an event
	 * @param consumer tool consuming an event
	 * 
	 */
	private String getKey(PluginTool producer, PluginTool consumer) {
		return producer.getName() + "+" + consumer.getName();
	}

	private void updateConnections(PropertyChangeEvent ev) {

		PluginTool tool = (PluginTool) ev.getSource();
		updateConnectMap(tool);

		// notify listeners of tool change
		firePropertyChangeEvent(ev);
	}

	private void firePropertyChangeEvent(PropertyChangeEvent ev) {
		// notify listeners of tool change
		for (int i = 0; i < changeListeners.size(); i++) {
			WorkspaceChangeListener l = changeListeners.get(i);
			l.propertyChange(ev);
		}
	}

	private boolean isDefaultWorkspaceName(String name) {
		if (!name.startsWith(DEFAULT_WORKSPACE_NAME)) {
			return false;
		}
		if (name.equals(DEFAULT_WORKSPACE_NAME) || name.startsWith(DEFAULT_WORKSPACE_NAME + " (")) {
			return true;
		}
		return false;
	}

	private String getUniqueWorkspaceName() {
		String name = DEFAULT_WORKSPACE_NAME;
		String baseName = name;
		int count = 0;
		while (wsMap.containsKey(name)) {
			++count;
			name = baseName + " (" + count + ")";
		}
		return name;
	}

	public boolean canAutoSave(PluginTool tool) {
		ToolSaveStatus status = toolStatusMap.get(tool.getToolName());
		if (status == ToolSaveStatus.ASK_SAVE_MODE) {
			return false;
		}

		// we are in auto mode...if there is only one tool, then we can auto save
		if (getToolInstanceCount(tool) == 1) {
			return true;
		}

		// otherwise, lazy update the status...things may have changed
		if (tool.hasConfigChanged()) {
			status = ToolSaveStatus.ASK_SAVE_MODE;
			toolStatusMap.put(tool.getToolName(), status);
		}

		return (status == ToolSaveStatus.AUTO_SAVE_MODE);
	}

	public void toolSaved(PluginTool tool, boolean toolChanged) {
		String toolName = tool.getToolName();
		if (getToolInstanceCount(tool) == 1) {
			// saving with only one instance open resets the status
			toolStatusMap.put(toolName, ToolSaveStatus.AUTO_SAVE_MODE);
		}
		else if (toolChanged) {
			// if there is more that one tool open and a changed tool is saved, go into ask_mode
			toolStatusMap.put(toolName, ToolSaveStatus.ASK_SAVE_MODE);
		}
	}

	private int getToolInstanceCount(PluginTool tool) {
		List<PluginTool> list = namesMap.get(tool.getToolName());
		if (list == null) {
			return 0;
		}
		return list.size();
	}
}
