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
import java.net.URL;
import java.util.*;
import java.util.function.Function;

import org.jdom.Document;
import org.jdom.output.XMLOutputter;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.framework.ToolUtils;
import ghidra.framework.data.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.protocol.ghidra.GetUrlContentTypeTask;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.util.Msg;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.TaskLauncher;
import ghidra.util.xml.GenericXMLOutputter;
import util.CollectionUtils;

/**
 * Implementation of service used to manipulate tools.
 */
class ToolServicesImpl implements ToolServices {

	private static String TOOL_ASSOCIATION_PREFERENCE = "ToolAssociation";
	private static String SEPARATOR = ":";

	private ToolChest toolChest;
	private ToolManagerImpl toolManager;
	private ToolChestChangeListener toolChestChangeListener;

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
		fileChooser.dispose();
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
			File dir = new File(exportDir);
			if (dir.isDirectory()) {
				newFileChooser.setCurrentDirectory(dir);
			}
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

	private static DefaultLaunchMode getDefaultLaunchMode() {
		DefaultLaunchMode defaultLaunchMode = DefaultLaunchMode.DEFAULT;
		FrontEndTool frontEndTool = AppInfo.getFrontEndTool();
		if (frontEndTool != null) {
			defaultLaunchMode = frontEndTool.getDefaultLaunchMode();
		}
		return defaultLaunchMode;
	}

	private PluginTool defaultLaunch(ToolTemplate template,
			Function<PluginTool, Boolean> openFunction) {

		DefaultLaunchMode defaultLaunchMode = getDefaultLaunchMode();
		if (defaultLaunchMode == DefaultLaunchMode.REUSE_TOOL) {
			if (template != null) {
				// attempt to reuse running tool with default name
				String defaultToolName = template.getName();
				for (PluginTool tool : getRunningTools()) {
					if (tool.getName().equals(defaultToolName) && openFunction.apply(tool)) {
						return tool;
					}
				}
			}

			// attempt to reuse any running tool
			for (PluginTool tool : getRunningTools()) {
				if (openFunction.apply(tool)) {
					return tool;
				}
			}
		}

		if (template == null) {
			return null; // unable to launch new tool
		}

		Workspace workspace = toolManager.getActiveWorkspace();
		PluginTool tool = workspace.runTool(template);
		if (tool == null) {
			return null; // tool launch failed
		}
		tool.setVisible(true);
		openFunction.apply(tool);
		return tool;
	}

	@Override
	public PluginTool launchDefaultTool(Collection<DomainFile> domainFiles) {
		if (CollectionUtils.isBlank(domainFiles)) {
			throw new IllegalArgumentException("Domain files cannot be empty");
		}
		ToolTemplate template = getDefaultToolTemplate(CollectionUtils.any(domainFiles));
		return defaultLaunch(template, t -> {
			return t.acceptDomainFiles(domainFiles.toArray(DomainFile[]::new));
		});
	}

	@Override
	public PluginTool launchTool(String toolName, Collection<DomainFile> domainFiles) {
		ToolTemplate template = findToolChestToolTemplate(toolName);
		if (template == null) {
			return null;
		}
		return defaultLaunch(template, t -> {
			if (CollectionUtils.isBlank(domainFiles)) {
				return true;
			}
			return t.acceptDomainFiles(domainFiles.toArray(DomainFile[]::new));
		});
	}

	@Override
	public PluginTool launchDefaultToolWithURL(URL ghidraUrl) throws IllegalArgumentException {
		String contentType = getContentType(ghidraUrl);
		if (contentType == null) {
			return null;
		}
		ToolTemplate template = getDefaultToolTemplate(contentType);
		return defaultLaunch(template, t -> {
			return t.accept(ghidraUrl);
		});
	}

	@Override
	public PluginTool launchToolWithURL(String toolName, URL ghidraUrl)
			throws IllegalArgumentException {
		if (!GhidraURL.isLocalProjectURL(ghidraUrl) &&
			!GhidraURL.isServerRepositoryURL(ghidraUrl)) {
			throw new IllegalArgumentException("unsupported URL");
		}
		ToolTemplate template = findToolChestToolTemplate(toolName);
		if (template == null) {
			return null;
		}
		Workspace workspace = toolManager.getActiveWorkspace();
		PluginTool tool = workspace.runTool(template);
		if (tool != null) {
			tool.accept(ghidraUrl);
		}
		return tool;
	}

	private String getContentType(URL url) throws IllegalArgumentException {
		GetUrlContentTypeTask task = new GetUrlContentTypeTask(url);
		TaskLauncher.launch(task); // blocking task
		return task.getContentType();
	}

	@Override
	public void setContentTypeToolAssociations(Set<ToolAssociationInfo> infos) {
		for (ToolAssociationInfo info : infos) {

			ContentHandler<?> handler = info.getContentHandler();
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
		Set<? extends ContentHandler<?>> handlers = DomainObjectAdapter.getContentHandlers();
		for (ContentHandler<?> contentHandler : handlers) {
			if (contentHandler instanceof LinkHandler) {
				continue;
			}
			set.add(createToolAssociationInfo(contentHandler));
		}

		return set;
	}

	private ToolAssociationInfo createToolAssociationInfo(ContentHandler<?> contentHandler) {
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
		return getDefaultToolTemplate(domainFile.getContentType());
	}

	@Override
	public ToolTemplate getDefaultToolTemplate(String contentType) {

		try {
			ContentHandler<?> contentHandler = DomainObjectAdapter.getContentHandler(contentType);
			if (contentHandler instanceof LinkHandler) {
				Class<? extends DomainObjectAdapter> domainObjectClass =
					contentHandler.getDomainObjectClass();
				contentHandler = DomainObjectAdapter.getContentHandler(domainObjectClass);
				contentType = contentHandler.getContentType();
			}
		}
		catch (IOException e) {
			// Failed to identify content handler
			Msg.error(this, e.getMessage());
			return null;
		}

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
		// Next, check content handler for its default tool name
		//
		try {
			ContentHandler<?> handler = DomainObjectAdapter.getContentHandler(domainClass);
			String defaultToolName = handler.getDefaultToolName();
			if (nameToTemplateMap.get(defaultToolName) == null) {
				ToolTemplate toolChestTemplate = findToolChestToolTemplate(defaultToolName);
				if (toolChestTemplate != null) {
					// found the tool in the tool chest--use that one
					nameToTemplateMap.put(toolChestTemplate.getName(), toolChestTemplate);
				}
				else {
					// see if there is a default tool
					GhidraToolTemplate defaultToolTemplate =
						findDefaultToolTemplate(defaultToolName);
					if (defaultToolTemplate != null) {
						nameToTemplateMap.put(defaultToolTemplate.getName(), defaultToolTemplate);
					}
				}
			}
		}
		catch (IOException e) {
			// Failed to identify content handler
			Msg.error(this, e.getMessage());
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

	private String getToolAssociationPreferenceKey(String contentType) {
		return TOOL_ASSOCIATION_PREFERENCE + SEPARATOR + contentType;
	}

	private String getDefaultToolAssociation(String contentType) {

		try {
			ContentHandler<?> contentHandler = DomainObjectAdapter.getContentHandler(contentType);
			return contentHandler.getDefaultToolName();
		}
		catch (IOException e) {
			// Failed to identify content handler
			Msg.error(this, e.getMessage());
		}
		return null;
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

	@Override
	public PluginTool[] getRunningTools() {
		return toolManager.getRunningTools();
	}

	@Override
	public boolean canAutoSave(PluginTool tool) {
		return toolManager.canAutoSave(tool);
	}
}
