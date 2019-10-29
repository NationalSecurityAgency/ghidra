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
package ghidra.framework;

import java.io.*;
import java.util.*;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

import ghidra.framework.model.ProjectManager;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.project.tool.GhidraToolTemplate;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;
import resources.ResourceManager;

public class ToolUtils {

	public static final String TOOL_EXTENSION = ".tool";
	private static final Logger LOGGER = LogManager.getLogger(ToolUtils.class);
	private static final File USER_TOOLS_DIR = new File(getApplicationToolDirPath());

	private static Set<ToolTemplate> allTools;
	private static Set<ToolTemplate> defaultTools;
	private static Set<ToolTemplate> extraTools;

	// this can be changed reflectively
	private static boolean allowTestTools = SystemUtilities.isInTestingMode();

	private ToolUtils() {
		// utils class
	}

	public static File getUserToolsDirectory() {
		return USER_TOOLS_DIR;
	}

	/**
	 * Returns all tools found in the classpath that live under a root
	 * 'defaultTools' directory
	 * 
	 * @return the default tools
	 */
	// synchronized to protect loading of static set
	public static synchronized Set<ToolTemplate> getDefaultApplicationTools() {
		if (defaultTools != null) {
			return defaultTools;
		}

		Set<ToolTemplate> set = new HashSet<>();

		Set<String> toolNames = ResourceManager.getResourceNames("defaultTools", ".tool");
		for (String toolName : toolNames) {
			if (skipTool(toolName)) {
				continue;
			}

			ToolTemplate tool = readToolTemplate(toolName);
			if (tool != null) {
				set.add(tool);
			}
		}

		defaultTools = Collections.unmodifiableSet(set);
		return defaultTools;
	}

	/**
	 * Returns all tools found in the classpath that live under a root
	 * 'extraTools' directory
	 * 
	 * @return the extra tools
	 */
	// synchronized to protect loading of static set
	public static synchronized Set<ToolTemplate> getExtraApplicationTools() {
		if (extraTools != null) {
			return extraTools;
		}

		Set<ToolTemplate> set = new HashSet<>();

		Set<String> extraToolsList = ResourceManager.getResourceNames("extraTools", ".tool");
		for (String toolName : extraToolsList) {
			ToolTemplate tool = readToolTemplate(toolName);
			if (tool != null) {
				set.add(tool);
			}
		}

		extraTools = Collections.unmodifiableSet(set);
		return extraTools;
	}

	/**
	 * Returns all tools found in the classpath that live under a root
	 * 'defaultTools' directory or a root 'extraTools' directory
	 * 
	 * @return the tools
	 */
	// synchronized to protect loading of static set
	public static synchronized Set<ToolTemplate> getAllApplicationTools() {
		if (allTools != null) {
			return allTools;
		}

		Set<ToolTemplate> set = new HashSet<>();
		set.addAll(getDefaultApplicationTools());
		set.addAll(getExtraApplicationTools());

		allTools = Collections.unmodifiableSet(set);
		return allTools;
	}

	public static Map<String, ToolTemplate> loadUserTools() {
		FilenameFilter filter =
			(dir, name) -> name.endsWith(ProjectManager.APPLICATION_TOOL_EXTENSION);

		// we want sorting by tool name, so use a sorted map
		Map<String, ToolTemplate> map = new TreeMap<>();
		File[] toolFiles = USER_TOOLS_DIR.listFiles(filter);
		if (toolFiles != null) {
			for (File toolFile : toolFiles) {
				ToolTemplate template = ToolUtils.readToolTemplate(toolFile);
				if (template != null) {
					map.put(template.getName(), template);
				}
			}
		}

		return map;
	}

	public static void removeInvalidPlugins(ToolTemplate template) {
		// parse the XML to see what plugins are loaded
		Element xmlRoot = template.saveToXml();

		// get out the tool element of the high-level tool
		Element toolElement = xmlRoot.getChild("TOOL");

		// the content of the tool xml consists of:
		// -option manager content
		// -plugin manager content
		// -window manager content

		// plugins are stored by adding content from SaveState objects, one per
		// plugin
		List<?> children = toolElement.getChildren("PLUGIN");
		Object[] childArray = children.toArray(); // we may modify this list,
		// so we need an array
		for (Object object : childArray) {
			Element pluginElement = (Element) object;
			Attribute classAttribute = pluginElement.getAttribute("CLASS");
			String value = classAttribute.getValue();

			// check to see if we can still find the plugin class (it may have
			// been removed)
			try {
				Class.forName(value);
			}
			catch (Throwable t) {
				// oh well, leave it out
				// TOOL: should we inform the user about these at some point?
				LOGGER.info("Removing invalid plugin " + pluginElement.getAttributeValue("CLASS") +
					" from tool: " + template.getName());
				toolElement.removeContent(pluginElement);
			}
		}

		// force the changes
		template.restoreFromXml(xmlRoot);
	}

	public static void deleteTool(ToolTemplate template) {
		USER_TOOLS_DIR.mkdirs();
		String name = template.getName();
		File toolFile = getToolFile(name);
		if (toolFile == null) {
			return;
		}

		toolFile.delete();
	}

	public static void renameToolTemplate(ToolTemplate toolTemplate, String newName) {
		ToolUtils.deleteTool(toolTemplate);
		toolTemplate.setName(newName);
		ToolUtils.writeToolTemplate(toolTemplate);
	}

	public static boolean writeToolTemplate(ToolTemplate template) {

		USER_TOOLS_DIR.mkdirs();
		String toolName = template.getName();
		File toolFile = getToolFile(toolName);

		boolean status = false;
		try (OutputStream os = new FileOutputStream(toolFile)) {

			Element element = template.saveToXml();
			Document doc = new Document(element);
			XMLOutputter xmlout = new GenericXMLOutputter();
			xmlout.output(doc, os);
			os.close();

			status = true;

		}
		catch (Exception e) {
			Msg.error(LOGGER, "Error saving tool: " + toolName, e);
		}
		return status;
	}

	public static ToolTemplate readToolTemplate(File toolFile) {
		GhidraToolTemplate toolTemplate = null;
		try (FileInputStream is = new FileInputStream(toolFile)) {

			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);

			Document doc = sax.build(is);
			Element root = doc.getRootElement();

			toolTemplate = new GhidraToolTemplate(root, toolFile.getAbsolutePath());
		}
		catch (FileNotFoundException e) {
			throw new AssertException(
				"We should only be passed valid files. Cannot find: " + toolFile.getAbsolutePath());
		}
		catch (JDOMException e) {
			Msg.error(LOGGER, "Error reading XML for " + toolFile, e);
		}
		catch (Exception e) {
			Msg.error(LOGGER, "Can't read tool template for " + toolFile, e);
		}

		updateFilenameToMatchToolName(toolFile, toolTemplate);

		return toolTemplate;
	}

	private static void updateFilenameToMatchToolName(File toolFile,
			GhidraToolTemplate toolTemplate) {
		if (toolTemplate == null) {
			return; // there must have been a problem creating the template
		}

		File correctToolFile = getToolFile(toolTemplate.getName());
		if (correctToolFile.equals(toolFile)) {
			return; // nothing to update
		}

		if (removeLastExtension(correctToolFile.getName()).equals(
			NamingUtilities.mangle(toolTemplate.getName()))) {
			return; // nothing to update
		}

		// If we get here, then we have two differently named files (the new one needs to replace
		// the outdated old one).  Make sure the files live in the same directory (otherwise, 
		// we can't delete the old one (this implies it is a default tool)).
		if (correctToolFile.getParentFile().equals(toolFile.getParentFile())) {
			// same parent directory, but different filename
			toolFile.delete();
		}

		writeToolTemplate(toolTemplate);
	}

	private static String removeLastExtension(String filename) {
		int period = filename.lastIndexOf('.');
		if (period == -1) {
			return filename;
		}
		return filename.substring(0, period);
	}

	public static ToolTemplate readToolTemplate(String resourceFileName) {

		try (InputStream is = ResourceManager.getResourceAsStream(resourceFileName)) {
			if (is == null) {
				return null;
			}
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			Document doc = sax.build(is);
			Element root = doc.getRootElement();

			return new GhidraToolTemplate(root, resourceFileName);
		}
		catch (JDOMException e) {
			Msg.error(LOGGER, "Error reading XML for resource " + resourceFileName, e);
		}
		catch (Exception e) {
			Msg.error(LOGGER, "Can't read tool template for resource " + resourceFileName, e);
		}

		return null;
	}

	private static boolean skipTool(String toolName) {
		if (allowTestTools) {
			return false;
		}

		if (StringUtils.containsIgnoreCase(toolName, "test")) {
			LOGGER.trace("Not adding default 'test' tool: " + toolName);
			return true;
		}

		return false;
	}

	public static String getUniqueToolName(ToolTemplate template) {
		String name = template.getName();
		int n = 1;
		while (ToolUtils.getToolFile(name).exists()) {
			name = name + "_" + n++;
		}
		return name;
	}

	private static File getToolFile(File dir, String toolName) {
		return new File(dir,
			NamingUtilities.mangle(toolName) + ProjectManager.APPLICATION_TOOL_EXTENSION);
	}

	public static File getToolFile(String name) {
		return getToolFile(USER_TOOLS_DIR, name);
	}

	/**
	 * Returns the user's personal tool chest directory path
	 * @return the path
	 */
	public static String getApplicationToolDirPath() {
		String userSettingsPath = Application.getUserSettingsDirectory().getAbsolutePath();
		return userSettingsPath + File.separatorChar + ProjectManager.APPLICATION_TOOLS_DIR_NAME;
	}
}
