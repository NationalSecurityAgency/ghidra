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

import java.util.*;

import org.jdom.Element;

import ghidra.framework.model.ToolTemplate;
import ghidra.framework.model.Workspace;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.exception.DuplicateNameException;

/**
 * WorkspaceImpl
 * 
 * Implementation of a Workspace.
 * 
 */
class WorkspaceImpl implements Workspace {
	private final static int TYPICAL_NUM_RUNNING_TOOLS = 5;

	private String name;
	private ToolManagerImpl toolManager;
	private Set<PluginTool> runningTools = new HashSet<PluginTool>(TYPICAL_NUM_RUNNING_TOOLS);
	private boolean isActive;

	WorkspaceImpl(String name, ToolManagerImpl toolManager) {
		this.name = name;
		this.toolManager = toolManager;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public PluginTool[] getTools() {
		PluginTool[] tools = new PluginTool[runningTools.size()];
		runningTools.toArray(tools);
		return tools;
	}

	@Override
	public PluginTool createTool() {
		// launch the empty tool
		PluginTool emptyTool = toolManager.createEmptyTool();

		// add the new  tool to our list of running tools
		runningTools.add(emptyTool);
		emptyTool.setVisible(true);

		// alert the tool manager that we changed
		toolManager.setWorkspaceChanged(this);
		toolManager.fireToolAddedEvent(this, emptyTool);

		return emptyTool;
	}

	@Override
	public PluginTool runTool(ToolTemplate template) {

		PluginTool tool = toolManager.getTool(this, template);
		if (tool != null) {
			tool.setVisible(true);

			if (tool instanceof GhidraTool) {
				GhidraTool gTool = (GhidraTool) tool;
				gTool.checkForNewExtensions();
			}
			runningTools.add(tool);

			// alert the tool manager that we changed
			toolManager.setWorkspaceChanged(this);
			toolManager.fireToolAddedEvent(this, tool);
		}
		return tool;
	}

	@Override
	public void setName(String newName) throws DuplicateNameException {

		toolManager.setWorkspaceName(this, newName);
		// alert the tool manager that we changed
		toolManager.setWorkspaceChanged(this);
		name = newName;
	}

	@Override
	public void setActive() {
		toolManager.setActiveWorkspace(this);
		setVisible(true);
	}

	/**
	 * Returns a string representation of the object. In general, the
	 * <code>toString</code> method returns a string that
	 * "textually represents" this object. The result should
	 * be a concise but informative representation that is easy for a
	 * person to read.
	 *
	 * @return  a string representation of the object.
	 */
	@Override
	public String toString() {
		return name;
	}

	/**
	 * saves the object to an XML element
	 * 
	 * @return an XML element containing the saved state
	 */
	public Element saveToXml() {

		Element root = new Element("WORKSPACE");
		root.setAttribute("NAME", name);
		root.setAttribute("ACTIVE", "" + isActive);

		for (PluginTool tool : runningTools) {
			Element elem = new Element("RUNNING_TOOL");
			elem.setAttribute("TOOL_NAME", tool.getToolName());
			elem.addContent(tool.saveWindowingDataToXml());
			elem.addContent(tool.saveDataStateToXml(true));

			root.addContent(elem);
		}
		return root;
	}

	/**
	 * restores the object from an XML element
	 * 
	 * @param root an XML element to restore from
	 */
	public void restoreFromXml(Element root) {
		String tmp = root.getAttributeValue("NAME");
		if (tmp != null) {
			name = tmp;
		}

		String activeStr = root.getAttributeValue("ACTIVE");
		isActive = (activeStr != null && activeStr.equalsIgnoreCase("true"));

		String defaultTool = System.getProperty("ghidra.defaulttool");
		if (defaultTool != null && !defaultTool.equals("")) {
			PluginTool tool = toolManager.getTool(defaultTool);
			runningTools.add(tool);
			toolManager.fireToolAddedEvent(this, tool);
			return;
		}

		Iterator<?> iter = root.getChildren("RUNNING_TOOL").iterator();
		while (iter.hasNext()) {
			Element element = (Element) iter.next();
			String toolName = element.getAttributeValue(ToolTemplate.TOOL_NAME_XML_NAME);
			if (toolName == null) {
				continue;
			}

			PluginTool tool = toolManager.getTool(toolName);
			if (tool != null) {
				tool.setVisible(isActive);

				if (tool instanceof GhidraTool) {
					GhidraTool gTool = (GhidraTool) tool;
					gTool.checkForNewExtensions();
				}

				boolean hadChanges = tool.hasConfigChanged();
				tool.restoreWindowingDataFromXml(element);

				Element toolDataElem = element.getChild("DATA_STATE");
				tool.restoreDataStateFromXml(toolDataElem);
				if (hadChanges) {
					// restore the dirty state, which is cleared by the restoreDataState call
					tool.setConfigChanged(true);
				}

				runningTools.add(tool);
				toolManager.fireToolAddedEvent(this, tool);
			}
		}
	}

//==================================================================================================
// Package Methods
//==================================================================================================	

	void setVisible(boolean state) {
		isActive = state;
		PluginTool[] tools = getTools();
		for (PluginTool tool : tools) {
			tool.setVisible(state);
		}
	}

	void closeRunningTool(PluginTool tool) {
		// tool is already closed via the call that got us here, so just clean up
		runningTools.remove(tool);

		// alert the tool manager that we changed
		toolManager.setWorkspaceChanged(this);

		toolManager.toolRemoved(this, tool);
	}

	/**
	 * Close all running tools; called from the close() method in
	 * ToolManagerImpl which is called from the Project's close()
	 */
	void close() {
		for (PluginTool tool : runningTools) {
			try {
				tool.exit();
			}
			finally {
				toolManager.toolRemoved(this, tool);
			}
		}
		runningTools.clear();
	}

}
