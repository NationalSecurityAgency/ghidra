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
package ghidra.framework.project;

import java.io.*;
import java.net.URL;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.framework.GenericRunInfo;
import ghidra.framework.ToolUtils;
import ghidra.framework.client.*;
import ghidra.framework.data.TransientDataManager;
import ghidra.framework.model.*;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.store.LockException;
import ghidra.util.*;
import ghidra.util.exception.NotFoundException;
import utilities.util.FileUtilities;

/**
 * Implementation for a ProjectManager; creates, opens,
 * and deletes Projects. It also keeps track of recently opened projects.
 */
public class DefaultProjectManager implements ProjectManager {

	/**
	 * Preference name for the last opened project.
	 */
	private final static String LAST_OPENED_PROJECT = "LastOpenedProject";

	private static final Logger LOG = LogManager.getLogger(DefaultProjectManager.class);

	private static final String RECENT_PROJECTS = "RecentProjects";
	private static final String VIEWED_PROJECTS = "ViewedProjects";
	private static final String SERVER_INFO = "ServerInfo";
	private static final int RECENT_PROJECTS_LIMIT = 6;
	private static String PROJECT_PATH_SEPARATOR = ";";

	private List<ProjectLocator> recentlyOpenedProjectsList;
	private List<URL> recentlyViewedProjectsList;

	private ToolChest userToolChest;
	private ServerInfo serverInfo;
	private ProjectLocator lastOpenedProject;
	private Project currentProject;

	/**
	 * Construct the single project manager.
	 */
	protected DefaultProjectManager() {
		recentlyOpenedProjectsList = new ArrayList<>();
		recentlyViewedProjectsList = new ArrayList<>();
		createUserToolChest();
		// get locator for last opened project
		lastOpenedProject = getLastOpenedProject();
		// read known projects from ghidra preferences...
		populateProjectLocatorList(recentlyOpenedProjectsList, RECENT_PROJECTS);
		populateProjectURLList(recentlyViewedProjectsList, VIEWED_PROJECTS);
		updatePreferences();
		serverInfo = getServerInfo(Preferences.getProperty(SERVER_INFO));
	}

	@Override
	public Project getActiveProject() {
		return currentProject;
	}

	@Override
	public Project createProject(ProjectLocator projectLocator, RepositoryAdapter repAdapter,
			boolean remember) throws IOException {

		if (currentProject != null) {
			Msg.error(this,
				"Current project must be closed before establishing a new active project");
			return null;
		}

		if (!projectLocator.getMarkerFile().getParentFile().isDirectory()) {
			throw new FileNotFoundException(
				"Directory not found: " + projectLocator.getMarkerFile().getParentFile());
		}

		try {
			currentProject = new DefaultProject(this, projectLocator, repAdapter);
		}
		catch (LockException e) {
			throw new IOException(e.getMessage());
		}

		if (remember) {
			addProjectToList(recentlyOpenedProjectsList, projectLocator);
			lastOpenedProject = projectLocator;
			updatePreferences();
		}
		return currentProject;
	}

	@Override
	public Project openProject(ProjectLocator projectLocator, boolean doRestore, boolean resetOwner)
			throws NotFoundException, NotOwnerException, LockException {

		if (currentProject != null) {
			Msg.error(this,
				"Current project must be closed before establishing a new active project");
			return null;
		}

		if (!projectLocator.getMarkerFile().exists()) {
			forgetProject(projectLocator);
			throw new NotFoundException(
				"Project marker file not found: " + projectLocator.getMarkerFile());
		}

		if (!projectLocator.getProjectDir().isDirectory()) {
			forgetProject(projectLocator);
			throw new NotFoundException(
				"Project directory not found: " + projectLocator.getProjectDir());
		}

		try {
			currentProject = new DefaultProject(this, projectLocator, resetOwner);
			if (doRestore) {
				currentProject.restore();
			}
			// success
			addProjectToList(recentlyOpenedProjectsList, projectLocator);
			lastOpenedProject = projectLocator;
			updatePreferences();
			return currentProject;
		}
		catch (LockException e) {
			return null;
		}
		catch (ReadOnlyException e) {
			Msg.showError(LOG, null, "Read-only Project!",
				"Cannot open project for update: " + projectLocator);
		}
		catch (IOException e) {
			Msg.showError(LOG, null, "Open Project Failed!",
				"Could not open project " + projectLocator + "\n \nCAUSE: " + e.getMessage());
		}
		finally {
			if (currentProject == null) {
				File dirFile = projectLocator.getProjectDir();
				if (!dirFile.exists() || !dirFile.isDirectory()) {
					forgetProject(projectLocator);
				}
			}
		}
		return null;
	}

	/**
	 * Get list of project locations that user most recently opened.
	 * @return list of project locations
	 */
	@Override
	public ProjectLocator[] getRecentProjects() {
		ProjectLocator[] projectLocators = new ProjectLocator[recentlyOpenedProjectsList.size()];
		return recentlyOpenedProjectsList.toArray(projectLocators);
	}

	@Override
	public URL[] getRecentViewedProjects() {
		URL[] urls = new URL[recentlyViewedProjectsList.size()];
		return recentlyViewedProjectsList.toArray(urls);
	}

	/**
	 * Get the last opened (active) project.
	 * @return project last opened by the user; returns NULL if a project
	 * was never opened OR the last opened project is no longer valid
	 */
	@Override
	public ProjectLocator getLastOpenedProject() {
		String projectPath = Preferences.getProperty(LAST_OPENED_PROJECT);
		if (projectPath == null || projectPath.trim().length() == 0) {
			return null;
		}
		return getLocatorFromProjectPath(projectPath);
	}

	/**
	 * Update the last opened project preference.
	 */
	@Override
	public void setLastOpenedProject(ProjectLocator projectLocator) {

		Preferences.setProperty(LAST_OPENED_PROJECT,
			projectLocator != null ? projectLocator.toString() : null);
		Preferences.store();
	}

	/**
	 * Delete the project in the given location and remove it from the list of known projects.
	 * 
	 * @return false if no project was deleted.
	 */
	@Override
	public boolean deleteProject(ProjectLocator projectLocator) {

		File dir = projectLocator.getProjectDir();
		File file = projectLocator.getMarkerFile();
		if (!dir.exists()) {
			throw new RuntimeException(file.getAbsolutePath() + " does not exist");
		}
		if (!dir.isDirectory()) {
			return false;
		}

		boolean didDelete = (FileUtilities.deleteDir(dir) && (!file.exists() || file.delete()));
		forgetProject(projectLocator);
		return didDelete;
	}

	/**
	 * Remove the specified project from the list of known projects.
	 */
	private void forgetProject(ProjectLocator projectLocator) {
		if (projectLocator == null) {
			return;
		}
		if (projectLocator.equals(lastOpenedProject)) {
			lastOpenedProject = null;
		}
		recentlyOpenedProjectsList.remove(projectLocator);
		updatePreferences();
	}

	/**
	 * Keep the specified project on the list of known projects.
	 */
	@Override
	public void rememberProject(ProjectLocator projectLocator) {
		if (!recentlyOpenedProjectsList.contains(projectLocator)) {
			addProjectToList(recentlyOpenedProjectsList, projectLocator);
			updatePreferences();
		}
	}

	@Override
	public void forgetViewedProject(URL url) {
		if (url == null) {
			return;
		}
		recentlyViewedProjectsList.remove(url);
		updatePreferences();
	}

	@Override
	public void rememberViewedProject(URL url) {
		if (!recentlyViewedProjectsList.contains(url)) {
			recentlyViewedProjectsList.add(0, url);
			if (recentlyViewedProjectsList.size() > RECENT_PROJECTS_LIMIT) {
				recentlyViewedProjectsList.remove(recentlyViewedProjectsList.size() - 1);
			}
			updatePreferences();
		}
	}

	/**
	 * Returns true if the specified project exists.
	 */
	@Override
	public boolean projectExists(ProjectLocator projectLocator) {
		return projectLocator.getProjectDir().exists();
	}

	@Override
	public RepositoryServerAdapter getRepositoryServerAdapter(String host, int portNumber,
			boolean forceConnect) {
		RepositoryServerAdapter rsh =
			ClientUtil.getRepositoryServer(host, portNumber, forceConnect);
		serverInfo = rsh.getServerInfo();
		updatePreferences();
		return rsh;
	}

	@Override
	public ServerInfo getMostRecentServerInfo() {
		return serverInfo;
	}

	/**
	 * Add the default tools to the given tool chest.  This method does not attempt to merge the
	 * user's previous tools, as does {@link #installTools(ToolChest)}.
	 * 
	 * @param toolChest tool chest which to add the default tools
	 */
	public void addDefaultTools(ToolChest toolChest) {

		Set<ToolTemplate> tools = ToolUtils.getDefaultApplicationTools();
		if (tools == null || tools.isEmpty()) {
			Msg.showError(LOG, null, "Default Tools Not Found",
				"Could not find default tools for project.");
			return;
		}

		for (ToolTemplate template : tools) {
			addDefaultTool(toolChest, template);
		}
	}

	private void installTools(ToolChest toolChest) {
		LOG.debug("No tools found; Installing default tools");

		File recoveryDirectory = getMostRecentValidProjectDirectory();
		if (recoveryDirectory == null) {
			LOG.debug("\tno recent project directories found");
			addDefaultTools(toolChest);
			return;
		}

		// get old tools
		Set<ToolTemplate> tools = ToolUtils.getDefaultApplicationTools();
		if (tools == null || tools.isEmpty()) {
			Msg.showError(LOG, null, "Default Tools Not Found",
				"Could not find default tools for project.");
			return;
		}

		// get the user's exiting tool, adding any default tools they don't have 
		Set<ToolTemplate> preExistingUserTools = getPreExistingUserTools(recoveryDirectory);
		Collection<ToolTemplate> mergedTools =
			mergeDefaultToolsIntoExisting(tools, preExistingUserTools);
		for (ToolTemplate toolTemplate : mergedTools) {
			addDefaultTool(toolChest, toolTemplate);
		}
	}

	private File getMostRecentValidProjectDirectory() {
		List<File> ghidraUserDirsByTime = GenericRunInfo.getPreviousApplicationSettingsDirsByTime();
		if (ghidraUserDirsByTime.size() == 0) {
			return null;
		}

		// get the tools from the most recent projects first
		for (File ghidraUserDir : ghidraUserDirsByTime) {
			File[] listFiles = ghidraUserDir.listFiles();
			if (listFiles == null) { // empty ghidra dir
				continue;
			}

			for (File ghidraDirSubFile : listFiles) {
				if (ghidraDirSubFile.getName().equals(APPLICATION_TOOLS_DIR_NAME)) {
					return ghidraUserDir; // found a tools dir; move on
				}
			}
		}
		return null;
	}

	private Collection<ToolTemplate> mergeDefaultToolsIntoExisting(Set<ToolTemplate> defaultTools,
			Set<ToolTemplate> userTools) {

		if (userTools.isEmpty()) {
			// no previous tools--use default tools
			return new HashSet<>(defaultTools);
		}

		LOG.debug("Found the following default tools: ");
		for (ToolTemplate tool : defaultTools) {
			LOG.debug("-" + tool);
		}

		LOG.debug("Found existing tools; merging existing tools: ");
		for (ToolTemplate tool : userTools) {
			LOG.debug("-" + tool);
		}

		//@formatter:off
		Map<String, ToolTemplate> allTools = new HashMap<>();
		Map<String, ToolTemplate> defaultMap =
			defaultTools.stream()
						.collect(Collectors.toMap(t -> t.getName(), Function.identity()))
						;
		Map<String, ToolTemplate> userMap =
			userTools.stream()
					 .collect(Collectors.toMap(t -> t.getName(), Function.identity()))
					 ;
		allTools.putAll(defaultMap);
		allTools.putAll(userMap); // user tools last, overwriting the defaults; they are preferred 
		//@formatter:on

		return allTools.values();
	}

	private URL saveTool(ToolTemplate toolTemplate) throws Exception {
		if (!ToolUtils.writeToolTemplate(toolTemplate)) {
			return null;
		}

		File newFile = ToolUtils.getToolFile(toolTemplate.getName());
		if (newFile == null) {
			return null;
		}
		return newFile.toURI().toURL();
	}

	/* Gets tools from the user's last project */
	private Set<ToolTemplate> getPreExistingUserTools(File previousUserDir) {
		if (previousUserDir == null) {
			return Collections.emptySet();
		}

		FileFilter dirFilter =
			file -> file.isDirectory() && file.getName().equals(APPLICATION_TOOLS_DIR_NAME);
		File[] toolDirs = previousUserDir.listFiles(dirFilter);
		if (toolDirs == null || toolDirs.length != 1) {
			LOG.debug("No user tools found in '" + previousUserDir + "'");
			return Collections.emptySet();
		}

		File toolsDir = toolDirs[0];

		FileFilter filter = file -> file.getAbsolutePath().endsWith(APPLICATION_TOOL_EXTENSION);
		File[] toolFiles = toolsDir.listFiles(filter);

		Set<ToolTemplate> set = new HashSet<>();
		for (File toolFile : toolFiles) {
			ToolTemplate template = ToolUtils.readToolTemplate(toolFile);
			scrubUserTool(template);
			set.add(template);
		}

		return set;
	}

	private void scrubUserTool(ToolTemplate template) {
		ToolUtils.removeInvalidPlugins(template);
		try {
			saveTool(template);
		}
		catch (Exception e) {
			Msg.error(LOG,
				"Unable to save user tool '" + template.getName() + "': " + e.getMessage(), e);
		}
	}

	@Override
	public ToolChest getUserToolChest() {
		return userToolChest;
	}

	private void addDefaultTool(ToolChest toolChest, ToolTemplate template) {

		// this implies that there exist multiple *default* tools with the same name, which
		// is an error condition.
		if (toolChest.getToolTemplate(template.getName()) != null) {
			Msg.showWarn(LOG, null, "Error Adding Tool",
				"Found multiple default tools with the same name: " + template.getName() +
					".\nCheck the classpath for " +
					"entries that contain tools that share the same tool name");
		}

		// Note: we call replace here and not add, since we know that we want to put a new tool
		//       in by the given name.  At this point we can assume there are not yet any 
		//       tools to overwrite, since this method is only called when no tools existed and
		//       we are adding the default set.
		toolChest.replaceToolTemplate(template);
	}

	private void createUserToolChest() {

		userToolChest = new ToolChestImpl();
		try {
			if (userToolChest.getToolCount() == 0) {
				installTools(userToolChest);
			}
		}
		catch (Exception e) {
			Msg.showError(LOG, null, "Tool Chest Error", "Failed to create tool chest.", e);
		}
	}

	/**
	 * Add the project to the given list;
	 * most recently accessed projects are first in the list.
	 */
	private boolean addProjectToList(List<ProjectLocator> list, ProjectLocator projectLocator) {
		File file = projectLocator.getMarkerFile();
		if (!file.exists()) {
			return false;
		}
		File dirFile = projectLocator.getProjectDir();
		if (!dirFile.exists()) {
			return false;
		}
		list.remove(projectLocator);
		list.add(0, projectLocator);
		if (list.size() > RECENT_PROJECTS_LIMIT) {
			list.remove(list.size() - 1);
		}
		return true;
	}

	private void populateProjectLocatorList(List<ProjectLocator> list, String propertyName) {
		String projectNames = Preferences.getProperty(propertyName, null, true);
		if (projectNames == null) {
			return;
		}
// TODO: fixed pathSeparator should be used to allow preferences to be more portable between platforms
		StringTokenizer st = new StringTokenizer(projectNames, PROJECT_PATH_SEPARATOR);
		while (st.hasMoreElements()) {
			String path = (String) st.nextElement();
			ProjectLocator projectLocator = getLocatorFromProjectPath(path);
			if (projectLocator != null) {
				list.add(projectLocator);
				if (list.size() == RECENT_PROJECTS_LIMIT) {
					break;
				}
			}
		}

	}

	private ProjectLocator getLocatorFromProjectPath(String path) {
		try {
			URL url = GhidraURL.toURL(path);
			if (GhidraURL.localProjectExists(url)) {
				return GhidraURL.getProjectStorageLocator(url);
			}
		}
		catch (IllegalArgumentException e) {
			Msg.error(this, "Invalid project path: " + path);
		}
		return null;
	}

	private void populateProjectURLList(List<URL> list, String propertyName) {
		String projectNames = Preferences.getProperty(propertyName, null, true);
		if (projectNames == null) {
			return;
		}

		StringTokenizer st = new StringTokenizer(projectNames, PROJECT_PATH_SEPARATOR);
		while (st.hasMoreElements()) {
			String urlStr = (String) st.nextElement();
			try {
				URL url = GhidraURL.toURL(urlStr);
				if (GhidraURL.isLocalProjectURL(url) && !GhidraURL.localProjectExists(url)) {
					continue;
				}
				list.add(url);
				if (list.size() == RECENT_PROJECTS_LIMIT) {
					break;
				}
			}
			catch (IllegalArgumentException e) {
				Msg.error(this, "Invalid project path/URL: " + urlStr);
			}
		}

	}

	/**
	 * Update preferences file with list of known projects.
	 */
	void updatePreferences() {

		setProjectLocatorProperty(recentlyOpenedProjectsList, RECENT_PROJECTS);
		setProjectURLProperty(recentlyViewedProjectsList, VIEWED_PROJECTS);
		if (serverInfo != null) {
			Preferences.setProperty(SERVER_INFO,
				serverInfo.getServerName() + ":" + serverInfo.getPortNumber());
		}
		Preferences.setProperty(LAST_OPENED_PROJECT,
			lastOpenedProject != null ? lastOpenedProject.toString() : null);
		Preferences.store();
	}

	private void setProjectLocatorProperty(List<ProjectLocator> list, String propertyName) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < list.size(); i++) {
			ProjectLocator projectLocator = list.get(i);
			sb.append(projectLocator.toString());
			if (i < list.size() - 1) {
				sb.append(PROJECT_PATH_SEPARATOR);
			}
		}
		Preferences.setProperty(propertyName, sb.toString());
	}

	private void setProjectURLProperty(List<URL> list, String propertyName) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < list.size(); i++) {
			URL url = list.get(i);
			sb.append(url.toExternalForm());
			if (i < list.size() - 1) {
				sb.append(PROJECT_PATH_SEPARATOR);
			}
		}
		Preferences.setProperty(propertyName, sb.toString());
	}

	private ServerInfo getServerInfo(String str) {
		if (str == null) {
			return null;
		}
		String host = null;
		String portStr = null;

		StringTokenizer st = new StringTokenizer(str, ":");
		while (st.hasMoreTokens()) {
			if (host == null) {
				host = st.nextToken();
			}
			else {
				portStr = st.nextToken();
			}
		}

		if (host != null && portStr != null) {
			try {
				return new ServerInfo(host, Integer.parseInt(portStr));
			}
			catch (NumberFormatException e) {
				// just return null below
			}
		}
		return null;
	}

	void projectClosed(DefaultProject project) {
		if (project == currentProject) {
			currentProject = null;
		}
		TransientDataManager.clearAll();
	}

}
