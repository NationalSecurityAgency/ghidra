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

import java.io.*;
import java.util.*;

import org.jdom.Document;
import org.jdom.output.XMLOutputter;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.framework.ToolUtils;
import ghidra.framework.data.ContentHandler;
import ghidra.framework.data.DomainObjectAdapter;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.xml.GenericXMLOutputter;

/**
 * Implementation of service used to manipulate tools.
 */
class ToolServicesImpl implements ToolServices {

	private static String TOOL_ASSOCIATION_PREFERENCE = "ToolAssociation";
	private static String SEPARATOR = ":";

	private ToolChest toolChest;
	private ToolManagerImpl toolManager;
	private List<DefaultToolChangeListener> listeners = new ArrayList<>();
	private ToolChestChangeListener toolChestChangeListener;
	private Set<ContentHandler> contentHandlers;

	ToolServicesImpl(ToolChest toolChest, ToolManagerImpl toolManager) {
		this.toolChest = toolChest;
		this.toolManager = toolManager;
	}

	void dispose() {
		toolChest.removeToolChestChangeListener(toolChestChangeListener);
	}

	@Override
	public void closeTool(PluginTool tool) {
		toolManager.closeTool(tool);
	}

	@Override
	public File exportTool(ToolTemplate tool) throws FileNotFoundException, IOException {

		File location = chooseToolFile(tool);
		if (location == null) {
			return location; // user cancelled
		}

		String filename = location.getName();
		if (!filename.endsWith(ToolUtils.TOOL_EXTENSION)) {
			filename = filename + ToolUtils.TOOL_EXTENSION;
		}

		try (FileOutputStream f =
			new FileOutputStream(location.getParent() + File.separator + filename)) {
			BufferedOutputStream bf = new BufferedOutputStream(f);
			Document doc = new Document(tool.saveToXml());
			XMLOutputter xmlout = new GenericXMLOutputter();
			xmlout.output(doc, bf);
		}

		return location;
	}

	private File chooseToolFile(ToolTemplate tool) {
		GhidraFileChooser fileChooser = getFileChooser();

		File exportFile = null;
		while (exportFile == null) {
			exportFile = fileChooser.getSelectedFile(); // show the chooser
			if (exportFile == null) {
				return null; // user cancelled
			}

			Preferences.setProperty(Preferences.LAST_TOOL_EXPORT_DIRECTORY, exportFile.getParent());
			if (!exportFile.getName().endsWith(ToolUtils.TOOL_EXTENSION)) {
				exportFile = new File(exportFile.getAbsolutePath() + ToolUtils.TOOL_EXTENSION);
			}

			if (exportFile.exists()) {
				int result = OptionDialog.showOptionDialog(null, "Overwrite?",
					"Overwrite existing file: '" + exportFile.getName() + "'?", "Overwrite",
					OptionDialog.QUESTION_MESSAGE);
				if (result != OptionDialog.OPTION_ONE) {
					exportFile = null; // user chose not to overwrite
				}
			}
		}

		return exportFile;
	}

	private GhidraFileChooser getFileChooser() {
		GhidraFileChooser newFileChooser = new GhidraFileChooser(null);
		newFileChooser.setFileFilter(new GhidraFileFilter() {
			@Override
			public boolean accept(File file, GhidraFileChooserModel model) {
				if (file == null) {
					return false;
				}

				if (file.isDirectory()) {
					return true;
				}

				return file.getAbsolutePath().toLowerCase().endsWith("tool");
			}

			@Override
			public String getDescription() {
				return "Tools";
			}
		});

		String exportDir = Preferences.getProperty(Preferences.LAST_TOOL_EXPORT_DIRECTORY);
		if (exportDir != null) {
			newFileChooser.setCurrentDirectory(new File(exportDir));
		}

		newFileChooser.setTitle("Export Tool");
		newFileChooser.setApproveButtonText("Export");

		return newFileChooser;
	}

	@Override
	public void saveTool(PluginTool tool) {
		boolean toolChanged = tool.hasConfigChanged();
		ToolTemplate template = tool.saveToolToToolTemplate();
		toolManager.toolSaved(tool, toolChanged);
		toolChest.replaceToolTemplate(template);
		toolManager.setWorkspaceChanged((WorkspaceImpl) toolManager.getActiveWorkspace());
	}

	@Override
	public ToolChest getToolChest() {
		return toolChest;
	}

	@Override
	public void displaySimilarTool(PluginTool tool, DomainFile domainFile, PluginEvent event) {

		PluginTool[] similarTools = getSameNamedRunningTools(tool);
		PluginTool matchingTool = findToolUsingFile(similarTools, domainFile);
		if (matchingTool != null) {
			// Bring the matching tool forward.
			matchingTool.toFront();
		}
		else {
			// Create a new tool and pop it up.
			Workspace workspace = toolManager.getActiveWorkspace();
			matchingTool = workspace.runTool(tool.getToolTemplate(true));
			matchingTool.setVisible(true);
			matchingTool.acceptDomainFiles(new DomainFile[] { domainFile });
		}

		// Fire the indicated event in the tool.
		matchingTool.firePluginEvent(event);
	}

	@Override
	public PluginTool launchDefaultTool(DomainFile domainFile) {
		ToolTemplate template = getDefaultToolTemplate(domainFile);
		if (template != null) {
			Workspace workspace = toolManager.getActiveWorkspace();
			PluginTool tool = workspace.runTool(template);
			tool.setVisible(true);
			if (domainFile != null) {
				tool.acceptDomainFiles(new DomainFile[] { domainFile });
			}
			return tool;
		}
		return null;
	}

	@Override
	public PluginTool launchTool(String toolName, DomainFile domainFile) {
		ToolTemplate template = findToolChestToolTemplate(toolName);
		if (template != null) {
			Workspace workspace = toolManager.getActiveWorkspace();
			PluginTool tool = workspace.runTool(template);
			tool.setVisible(true);
			if (domainFile != null) {
				tool.acceptDomainFiles(new DomainFile[] { domainFile });
			}
			return tool;
		}
		return null;
	}

	@Override
	public void setContentTypeToolAssociations(Set<ToolAssociationInfo> infos) {
		for (ToolAssociationInfo info : infos) {

			ContentHandler handler = info.getContentHandler();
			String contentType = handler.getContentType();
			String preferenceKey = getToolAssociationPreferenceKey(contentType);
			if (!info.isDefault()) {
				ToolTemplate template = info.getCurrentTemplate();
				String toolName = template.getName();
				Preferences.setProperty(preferenceKey, toolName);
			}
			else {
				// remove the preference
				Preferences.setProperty(preferenceKey, null);
			}

			ensureToolIsInToolChest(info.getCurrentTemplate());
		}
		Preferences.store();
	}

	private void ensureToolIsInToolChest(ToolTemplate template) {
		if (template == null) {
			return;
		}

		ToolTemplate existingTemplate = toolChest.getToolTemplate(template.getName());
		if (existingTemplate != null) {
			return;
		}

		toolChest.addToolTemplate(template);
	}

	@Override
	public Set<ToolAssociationInfo> getContentTypeToolAssociations() {
		Set<ToolAssociationInfo> set = new HashSet<>();

		// get all known content types
		Set<ContentHandler> handlers = getContentHandlers();
		for (ContentHandler contentHandler : handlers) {
			set.add(createToolAssociationInfo(contentHandler));
		}

		return set;
	}

	private ToolAssociationInfo createToolAssociationInfo(ContentHandler contentHandler) {
		String contentType = contentHandler.getContentType();
		String defaultToolName = contentHandler.getDefaultToolName();
		String userPreferredToolName =
			Preferences.getProperty(getToolAssociationPreferenceKey(contentType), null, true);
		if (userPreferredToolName != null) {
			ToolTemplate userDefinedTemplate = findToolChestToolTemplate(userPreferredToolName);
			return new ToolAssociationInfo(contentHandler, userPreferredToolName,
				userDefinedTemplate, findDefaultToolTemplate(defaultToolName));
		}

		ToolTemplate defaultToolChestTemplate = findToolChestToolTemplate(defaultToolName);
		return new ToolAssociationInfo(contentHandler, defaultToolName, defaultToolChestTemplate,
			findDefaultToolTemplate(defaultToolName));
	}

	@Override
	public ToolTemplate getDefaultToolTemplate(DomainFile domainFile) {
		String contentType = domainFile.getContentType();

		String toolName =
			Preferences.getProperty(getToolAssociationPreferenceKey(contentType), null, true);
		if (toolName == null) {
			// never been set--lookup a hardcoded default
			toolName = getDefaultToolAssociation(contentType);
		}

		return findToolChestToolTemplate(toolName);
	}

	@Override
	public Set<ToolTemplate> getCompatibleTools(Class<? extends DomainObject> domainClass) {
		Map<String, ToolTemplate> nameToTemplateMap = new HashMap<>();

		//
		// First, get all compatible tools in the tool chest
		//
		ToolTemplate[] toolTemplates = toolChest.getToolTemplates();
		for (ToolTemplate toolTemplate : toolTemplates) {
			Class<?>[] types = toolTemplate.getSupportedDataTypes();
			for (Class<?> clazz : types) {
				if (clazz.isAssignableFrom(domainClass)) {
					nameToTemplateMap.put(toolTemplate.getName(), toolTemplate);
				}
			}
		}

		//
		// Next, look through for all compatible content handlers find tools for them
		//
		Set<ContentHandler> compatibleHandlers = getCompatibleContentHandlers(domainClass);
		for (ContentHandler handler : compatibleHandlers) {
			String defaultToolName = handler.getDefaultToolName();
			if (nameToTemplateMap.get(defaultToolName) != null) {
				continue; // already have tool in the map by this name; prefer that tool
			}

			ToolTemplate toolChestTemplate = findToolChestToolTemplate(defaultToolName);
			if (toolChestTemplate != null) {
				// found the tool in the tool chest--use that one
				nameToTemplateMap.put(toolChestTemplate.getName(), toolChestTemplate);
				continue;
			}

			// see if there is a default tool
			GhidraToolTemplate defaultToolTemplate = findDefaultToolTemplate(defaultToolName);
			if (defaultToolTemplate != null) {
				nameToTemplateMap.put(defaultToolTemplate.getName(), defaultToolTemplate);
			}
		}

		//
		// Finally, see if any of the default tools can handle this type and include any that
		// we haven't already included
		//
		Set<ToolTemplate> defaultTools = ToolUtils.getAllApplicationTools();
		for (ToolTemplate toolTemplate : defaultTools) {
			String toolName = toolTemplate.getName();
			if (nameToTemplateMap.get(toolName) != null) {
				continue; // already have tool in the map by this name; prefer that tool
			}

			Class<?>[] types = toolTemplate.getSupportedDataTypes();
			for (Class<?> clazz : types) {
				if (clazz.isAssignableFrom(domainClass)) {
					nameToTemplateMap.put(toolName, toolTemplate);
				}
			}
		}

		return new HashSet<>(nameToTemplateMap.values());
	}

	private Set<ContentHandler> getCompatibleContentHandlers(
			Class<? extends DomainObject> domainClass) {
		Set<ContentHandler> set = new HashSet<>();
		Set<ContentHandler> handlers = getContentHandlers();
		for (ContentHandler contentHandler : handlers) {
			Class<? extends DomainObject> handlerDomainClass =
				contentHandler.getDomainObjectClass();
			if (handlerDomainClass == domainClass) {
				set.add(contentHandler);
			}
		}
		return set;
	}

	private String getToolAssociationPreferenceKey(String contentType) {
		return TOOL_ASSOCIATION_PREFERENCE + SEPARATOR + contentType;
	}

	private String getDefaultToolAssociation(String contentType) {
		Set<ContentHandler> handlers = getContentHandlers();
		for (ContentHandler contentHandler : handlers) {
			String type = contentHandler.getContentType();
			if (type.equals(contentType)) {
				return contentHandler.getDefaultToolName();
			}
		}
		return null;
	}

	private Set<ContentHandler> getContentHandlers() {
		if (contentHandlers != null) {
			return contentHandlers;
		}

		contentHandlers = new HashSet<>();
		List<ContentHandler> instances = ClassSearcher.getInstances(ContentHandler.class);
		for (ContentHandler contentHandler : instances) {
			// a bit of validation
			String contentType = contentHandler.getContentType();
			if (contentType == null) {
				Msg.error(DomainObjectAdapter.class, "ContentHandler " +
					contentHandler.getClass().getName() + " does not specify a content type");
				continue;
			}

			String toolName = contentHandler.getDefaultToolName();
			if (toolName == null) {
				Msg.error(DomainObjectAdapter.class, "ContentHandler " +
					contentHandler.getClass().getName() + " does not specify a default tool");
				continue;
			}

			contentHandlers.add(contentHandler);
		}

		return contentHandlers;
	}

	@Override
	public void addDefaultToolChangeListener(DefaultToolChangeListener listener) {
		listeners.add(listener);
	}

	@Override
	public void removeDefaultToolChangeListener(DefaultToolChangeListener listener) {
		listeners.remove(listener);
	}

	private GhidraToolTemplate findToolChestToolTemplate(String toolName) {
		if (toolName != null) {
			return (GhidraToolTemplate) toolChest.getToolTemplate(toolName);
		}
		return null;
	}

	private GhidraToolTemplate findDefaultToolTemplate(String defaultToolName) {
		if (defaultToolName == null) {
			return null;
		}

		Set<ToolTemplate> defaultTools = ToolUtils.getAllApplicationTools();
		for (ToolTemplate toolTemplate : defaultTools) {
			if (defaultToolName.equals(toolTemplate.getName())) {
				return (GhidraToolTemplate) toolTemplate; // assuming this is safe--we do it elsewhere
			}
		}
		return null;
	}

	/**
	 * Get all running tools that have the same tool chest tool name as this one.
	 * 
	 * @param tool the tool for comparison.
	 * 
	 * @return array of tools that are running and named the same as this one.
	 */
	private PluginTool[] getSameNamedRunningTools(PluginTool tool) {
		String toolName = tool.getToolName();
		PluginTool[] tools = toolManager.getRunningTools();
		List<PluginTool> toolList = new ArrayList<>(tools.length);
		for (PluginTool element : tools) {
			if (toolName.equals(element.getToolName())) {
				toolList.add(element);
			}
		}
		return toolList.toArray(new PluginTool[toolList.size()]);
	}

	@Override
	public PluginTool[] getRunningTools() {
		return toolManager.getRunningTools();
	}

	/**
	 * Search the array of tools for one using the given domainFile.
	 * 
	 * @param tools array of tools to search
	 * @param domainFile domain file to find user of
	 * 
	 * @return first tool found to be using the domainFile
	 */
	private PluginTool findToolUsingFile(PluginTool[] tools, DomainFile domainFile) {
		PluginTool matchingTool = null;
		for (int toolNum = 0; (toolNum < tools.length) && (matchingTool == null); toolNum++) {
			PluginTool pTool = (PluginTool) tools[toolNum];
			// Is this tool the same as the type we are in.
			DomainFile[] df = pTool.getDomainFiles();
			for (DomainFile element : df) {
				if (domainFile.equals(element)) {
					matchingTool = tools[toolNum];
					break;
				}
			}
		}
		return matchingTool;
	}

	@Override
	public boolean canAutoSave(PluginTool tool) {
		return toolManager.canAutoSave(tool);
	}
}
