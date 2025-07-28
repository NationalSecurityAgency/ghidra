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
import java.util.Map.Entry;

import org.jdom.*;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.data.DefaultProjectData;
import ghidra.framework.data.TransientDataManager;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.project.tool.GhidraToolTemplate;
import ghidra.framework.project.tool.ToolManagerImpl;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.protocol.ghidra.GhidraURLConnection;
import ghidra.framework.protocol.ghidra.GhidraURLConnection.StatusCode;
import ghidra.framework.store.LockException;
import ghidra.util.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;

/**
 * Implementation for a Project.
 */
public class DefaultProject implements Project {

	private static final String OPEN_VIEW_XML_NAME = "OPEN_VIEW";
	private static final String OPEN_REPOSITORY_VIEW_XML_NAME = "OPEN_REPOSITORY_VIEW";
	private static final String PROJECT_TOOL_CONFIG_XML_NAME = "PROJECT_TOOL_CONFIG";
	private static final String PROJECT_DATA_XML_NAME = "PROJECT_DATA_XML_NAME";

	private static final String PROJECT_STATE = "projectState";

	// this may be null
	private DefaultProjectManager projectManager;

	private ProjectLocator projectLocator;
	private DefaultProjectData projectData;
	private ToolManagerImpl toolManager;

	private boolean changed; // flag for whether the project configuration has changed
	private volatile boolean isClosed;

	private Map<String, SaveState> dataMap = new HashMap<>();
	private Map<String, ToolTemplate> projectConfigMap = new HashMap<>();
	private Map<URL, DefaultProjectData> otherViewsMap = new HashMap<>();
	private Set<URL> visibleViews = new HashSet<>();
	private WeakSet<ProjectViewListener> viewListeners =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	/**
	 * Constructor for creating a New project
	 * 
	 * @param projectManager the manager of this project
	 * @param projectLocator location and name of project
	 * @param repository shared repository associated with the new project. Can be null for
	 *            non-shared projects
	 * @throws IOException if I/O error occurs.
	 * @throws LockException if unable to establish project lock
	 */
	protected DefaultProject(DefaultProjectManager projectManager, ProjectLocator projectLocator,
			RepositoryAdapter repository) throws IOException, LockException {
		this.projectManager = projectManager;
		this.projectLocator = projectLocator;

		Msg.info(this, "Creating project: " + projectLocator.toString());
		projectData = new DefaultProjectData(projectLocator, repository, true);
		if (!SystemUtilities.isInHeadlessMode()) {
			toolManager = new ToolManagerImpl(this);
		}
		initializeNewProject();
	}

	/**
	 * Constructor for opening a project.
	 * 
	 * @param projectManager the manager of this project
	 * @param projectLocator location and name of project
	 * @param resetOwner if true, set the owner to the current user
	 * @throws FileNotFoundException project directory not found
	 * @throws IOException if I/O error occurs.
	 * @throws NotOwnerException if userName is not the owner of the project.
	 * @throws LockException if unable to establish project lock
	 */
	protected DefaultProject(DefaultProjectManager projectManager, ProjectLocator projectLocator,
			boolean resetOwner) throws IOException, NotOwnerException, LockException {

		this.projectManager = projectManager;
		this.projectLocator = projectLocator;

		Msg.info(this, "Opening project: " + projectLocator.toString());
		projectData = new DefaultProjectData(projectLocator, true, resetOwner);
		if (!SystemUtilities.isInHeadlessMode()) {
			toolManager = new ToolManagerImpl(this);
		}
	}

	/**
	 * Construct a project with specific project manager and data
	 * 
	 * @param projectManager the manager of this project
	 * @param projectData the project data
	 */
	protected DefaultProject(DefaultProjectManager projectManager, DefaultProjectData projectData) {

		this.projectManager = projectManager;
		this.projectData = projectData;

		projectLocator = projectData.getProjectLocator();
		if (!SystemUtilities.isInHeadlessMode()) {
			toolManager = new ToolManagerImpl(this);
		}

		initializeNewProject();
	}

	@Override
	public ProjectManager getProjectManager() {
		return projectManager;
	}

//	/**
//	 * Determine if the specified project location currently has a write lock.
//	 * @param locator project storage locator
//	 * @return true if project data current has write-lock else false
//	 */
//	public static boolean isLocked(ProjectLocator locator) {
//		ProjectLock lock = new ProjectLock(locator);
//		return lock.isLocked();
//	}

//	/**
//	 * Creates a ProjectLock and attempts to lock it. This handles the case
//	 * where the project was previously locked.
//	 * 
//	 * @param locator the project locator
//	 * @param allowInteractiveForce if true, when a lock cannot be obtained, the
//	 *            user will be prompted
//	 * @return A locked ProjectLock
//	 * @throws ProjectLockException if lock failed
//	 */
//	private ProjectLock getProjectLock(ProjectLocator locator, boolean allowInteractiveForce) {
//		ProjectLock lock = new ProjectLock(locator);
//		if (lock.lock()) {
//			return lock;
//		}
//
//		// in headless mode, just spit out an error
//		if (!allowInteractiveForce || SystemUtilities.isInHeadlessMode()) {
//			return null;
//		}
//
//		String projectStr = "Project: " + HTMLUtilities.escapeHTML(locator.getLocation()) +
//			System.getProperty("file.separator") + HTMLUtilities.escapeHTML(locator.getName());
//		String lockInformation = lock.getExistingLockFileInformation();
//		if (!lock.canForceLock()) {
//			Msg.showInfo(getClass(), null, "Project Locked",
//				"<html>Project is locked. You have another instance of Ghidra<br>" +
//					"already running with this project open (locally or remotely).<br><br>" +
//					projectStr + "<br><br>" + "Lock information: " + lockInformation);
//			return null;
//		}
//
//		int userChoice = OptionDialog.showOptionDialog(null, "Project Locked - Delete Lock?",
//			"<html>Project is locked. You may have another instance of Ghidra<br>" +
//				"already running with this project opened (locally or remotely).<br>" + projectStr +
//				"<br><br>" + "If this is not the case, you can delete the lock file:  <br><b>" +
//				locator.getProjectLockFile().getAbsolutePath() + "</b>.<br><br>" +
//				"Lock information: " + lockInformation,
//			"Delete Lock", OptionDialog.QUESTION_MESSAGE);
//		if (userChoice == OptionDialog.OPTION_ONE) { // Delete Lock
//			if (lock.forceLock()) {
//				return lock;
//			}
//
//			Msg.showError(this, null, "Error", "Attempt to force lock failed! " + locator);
//		}
//		return null;
//	}

	private void initializeNewProject() {
		if (toolManager == null) {
			return;
		}
		try {
			toolManager.createWorkspace(ToolManager.DEFAULT_WORKSPACE_NAME);
			toolManager.clearWorkspaceChanged();

		}
		catch (DuplicateNameException e) {
			Msg.showError(this, null, "Duplicate Name",
				"Error creating default workspace: " + e.getMessage());
		}
	}

	/**
	 * Get the project URL for this project.
	 */
	@Override
	public ProjectLocator getProjectLocator() {
		return projectLocator;
	}

	@Override
	public void addProjectViewListener(ProjectViewListener listener) {
		viewListeners.add(listener);
	}

	@Override
	public void removeProjectViewListener(ProjectViewListener listener) {
		viewListeners.remove(listener);
	}

	private void notifyVisibleViewAdded(URL projectView) {
		for (ProjectViewListener listener : viewListeners) {
			listener.viewedProjectAdded(projectView);
		}
	}

	private void notifyVisibleViewRemoved(URL projectView) {
		for (ProjectViewListener listener : viewListeners) {
			listener.viewedProjectRemoved(projectView);
		}
	}

	private ProjectData openProjectView(URL url) throws IOException {

		GhidraURLConnection c = (GhidraURLConnection) url.openConnection();
		c.setAllowUserInteraction(true);
		c.setReadOnly(true);

		StatusCode responseCode = c.getStatusCode();
		if (responseCode == StatusCode.NOT_FOUND) {
			throw new IOException(
				"Project/repository not found: " + GhidraURL.getDisplayString(url));
		}
		if (responseCode == StatusCode.UNAUTHORIZED) {
			// assume already informed
			return null;
		}

		DefaultProjectData veiwedProjectData = (DefaultProjectData) c.getProjectData();
		if (veiwedProjectData == null) {
			throw new IOException(
				"Failed to view specified project/repository: " + GhidraURL.getDisplayString(url));
		}
		url = veiwedProjectData.getProjectLocator().getURL(); // transform to repository root URL

		otherViewsMap.put(url, veiwedProjectData);
		return veiwedProjectData;
	}

	@Override
	public ProjectData addProjectView(URL url, boolean visible) throws IOException {
		synchronized (otherViewsMap) {
			if (isClosed) {
				throw new IOException("project is closed");
			}

			if (!GhidraURL.PROTOCOL.equals(url.getProtocol())) {
				throw new IOException("Invalid Ghidra URL specified: " + url);
			}

			if (url.equals(projectLocator.getURL())) {
				return projectData;
			}

			ProjectData viewedProjectData = otherViewsMap.get(url);
			if (viewedProjectData == null) {
				viewedProjectData = openProjectView(url);
			}

			if (viewedProjectData != null && visible && visibleViews.add(url)) {
				notifyVisibleViewAdded(url);
			}

			return viewedProjectData;
		}
	}

	@Override
	public ProjectData getProjectData(URL url) {

		if (url.equals(projectLocator.getURL())) {
			return projectData;
		}

		synchronized (otherViewsMap) {
			return otherViewsMap.get(url);
		}
	}

	/**
	 * Remove the view from this project.
	 */
	@Override
	public void removeProjectView(URL url) {
		synchronized (otherViewsMap) {
			DefaultProjectData dataMgr = otherViewsMap.remove(url);
			if (dataMgr != null) {
				if (visibleViews.remove(url)) {
					notifyVisibleViewRemoved(url);
				}
				dataMgr.close();
				Msg.info(this, "Closed project view: " + GhidraURL.getDisplayString(url));
				changed = true;
			}
		}
	}

	/**
	 * Get the tool services for this project.
	 */
	@Override
	public ToolServices getToolServices() {
		return toolManager != null ? toolManager.getToolServices() : null;
	}

	/**
	 * Get the local tool chest for the user logged in.
	 * 
	 * @return the tool chest
	 */
	@Override
	public ToolChest getLocalToolChest() {
		return projectManager.getUserToolChest();
	}

	@Override
	public String getName() {
		return projectLocator.getName();
	}

	@Override
	public ToolManager getToolManager() {
		return toolManager;
	}

	@Override
	public boolean hasChanged() {
		return changed || (toolManager != null && toolManager.hasChanged());
	}

	@Override
	public ProjectLocator[] getProjectViews() {

		// Only includes visible viewed projects
		ProjectData[] pd = getViewedProjectData();

		ProjectLocator[] views = new ProjectLocator[pd.length];
		for (int i = 0; i < pd.length; i++) {
			views[i] = pd[i].getProjectLocator();
		}
		return views;
	}

	@Override
	public RepositoryAdapter getRepository() {
		return projectData.getRepository();
	}

	@Override
	public void close() {
		synchronized (otherViewsMap) {
			isClosed = true;

			// Clear active project if this is the current active project.
			if (AppInfo.getActiveProject() == this) {
				AppInfo.setActiveProject(null);
			}

			for (DefaultProjectData dataMgr : otherViewsMap.values()) {
				if (dataMgr != null) {
					dataMgr.close();
				}
			}
			otherViewsMap.clear();
		}

		try {

			if (toolManager != null) {
				toolManager.dispose();
			}
			if (projectManager != null) {
				projectManager.projectClosed(this);
			}
		}
		finally {
			projectData.close();
		}
	}

	@Override
	public boolean isClosed() {
		return isClosed;
	}

	@Override
	public boolean saveSessionTools() {
		if (toolManager != null) {
			return toolManager.saveSessionTools();
		}
		return false;
	}

	@Override
	public void restore() {
		// if there is a saved project, restore it
		File saveFile = new File(projectData.getProjectDir(), PROJECT_STATE);
		String errorMsg = null;
		Throwable error = null;
		try {
			if (!saveFile.exists()) {
				initializeNewProject();
				return;
			}
			InputStream is = new FileInputStream(saveFile);
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);

			Element root = sax.build(is).getRootElement();

			// restore the saved tool template
			Iterator<?> it = root.getChildren(PROJECT_TOOL_CONFIG_XML_NAME).iterator();
			while (it.hasNext()) {
				Element elem = (Element) it.next();
				String name = elem.getAttributeValue("NAME");
				Element toolConfigElem = elem.getChild("TOOL_CONFIG");
				GhidraToolTemplate template =
					new GhidraToolTemplate(toolConfigElem, saveFile.getAbsolutePath());
				projectConfigMap.put(name, template);
			}

			List<?> dataChildren = root.getChildren(PROJECT_DATA_XML_NAME);
			for (Object object : dataChildren) {
				Element element = (Element) object;
				String name = element.getAttributeValue("NAME");
				List<?> saveStateChildren = element.getChildren("SAVE_STATE");
				for (Object saveStateObject : saveStateChildren) {
					SaveState saveState = new SaveState((Element) saveStateObject);
					dataMap.put(name, saveState);
				}
			}

			// restore the views that the user had showing
			it = root.getChildren(OPEN_VIEW_XML_NAME).iterator();
			while (it.hasNext()) {
				Element elem = (Element) it.next();
				String name = elem.getAttributeValue("NAME");
				String location = elem.getAttributeValue("LOCATION");
				URL url = GhidraURL.makeURL(location, name);
				try {
					addProjectView(url, true);
				}
				catch (IOException e) {
					Msg.error(this, "Project view not opended (" + GhidraURL.getDisplayString(url) +
						"): " + e.getMessage());
				}
			}
			it = root.getChildren(OPEN_REPOSITORY_VIEW_XML_NAME).iterator();
			while (it.hasNext()) {
				Element elem = (Element) it.next();
				String urlStr = elem.getAttributeValue("URL");
				URL url = new URL(urlStr);
				try {
					addProjectView(url, true);
				}
				catch (IOException e) {
					Msg.error(this, "Project view not opended (" + GhidraURL.getDisplayString(url) +
						"): " + e.getMessage());
				}
			}

			if (toolManager != null) {
				toolManager.restoreFromXml(root.getChild("TOOL_MANAGER"));
			}
			return;
		}
		catch (JDOMException e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			StringBuffer sb = new StringBuffer();
			StringTokenizer st = new StringTokenizer(msg, ":");
			while (st.hasMoreTokens()) {
				sb.append(st.nextToken());
				if (st.hasMoreTokens()) {
					sb.append("\n");
				}
			}
			errorMsg = "Invalid XML loading project " + projectLocator + ":\n" + sb.toString();
			error = e;
		}
		catch (NoClassDefFoundError e) {
			errorMsg = "Class definition missing: " + e;
			error = e;
		}
		catch (Exception e) {
			errorMsg = "Error restoring project " + projectLocator + "\n" + e;
			error = e;
		}
		Msg.showError(this, null, "Error Restoring Project", errorMsg, error);
		saveFile.delete();
		initializeNewProject();
	}

	@Override
	public void save() {

		if (toolManager == null) {
			return;
		}

		Element root = new Element("PROJECT");

		Set<Entry<String, ToolTemplate>> configEntrySet = projectConfigMap.entrySet();
		for (Entry<String, ToolTemplate> entry : configEntrySet) {
			String key = entry.getKey();
			ToolTemplate template = entry.getValue();

			Element elem = new Element(PROJECT_TOOL_CONFIG_XML_NAME);
			elem.setAttribute("NAME", key);
			elem.addContent(template.saveToXml());
			root.addContent(elem);
		}

		Set<Entry<String, SaveState>> entrySet = dataMap.entrySet();
		for (Entry<String, SaveState> entry : entrySet) {
			SaveState saveState = entry.getValue();
			Element element = new Element(PROJECT_DATA_XML_NAME);
			element.setAttribute("NAME", entry.getKey());
			element.addContent(saveState.saveToXml());
			root.addContent(element);
		}

		for (ProjectLocator view : getProjectViews()) {
			Element elem;
			if (!view.isTransient()) {
				elem = new Element(OPEN_VIEW_XML_NAME);
				elem.setAttribute("NAME", view.getName());
				elem.setAttribute("LOCATION", view.getLocation());
			}
			else {
				elem = new Element(OPEN_REPOSITORY_VIEW_XML_NAME);
				elem.setAttribute("URL", view.getURL().toExternalForm());
			}
			root.addContent(elem);
		}

		try {
			// save tool state
			root.addContent(toolManager.saveToXml()); // the tool manager will save the open tools' state
			File saveFile = new File(projectData.getProjectDir(), PROJECT_STATE);
			OutputStream os = new FileOutputStream(saveFile);
			Document doc = new Document(root);
			XMLOutputter xmlOut = new GenericXMLOutputter();
			xmlOut.output(doc, os);
			os.close();

			changed = false;

		}
		catch (Exception e) {
			Msg.showError(this, null, "Error", "Error saving project", e);
		}
		if (projectManager != null) {
			projectManager.updatePreferences();
		}
	}

	@Override
	public String toString() {
		return projectLocator.getName();
	}

	@Override
	public void saveToolTemplate(String tag, ToolTemplate template) {
		projectConfigMap.put(tag, template);
	}

	@Override
	public ToolTemplate getToolTemplate(String tag) {
		return projectConfigMap.get(tag);
	}

	@Override
	public List<DomainFile> getOpenData() {
		ArrayList<DomainFile> openFiles = new ArrayList<>();
		projectData.findOpenFiles(openFiles);
		ProjectData[] viewedProjs = getViewedProjectData();
		for (ProjectData viewedProj : viewedProjs) {
			((DefaultProjectData) viewedProj).findOpenFiles(openFiles);
		}
		List<DomainFile> list = new ArrayList<>();
		TransientDataManager.getTransients(list);
		for (DomainFile df : list) {
			if (df != null && df.isOpen()) {
				openFiles.add(df);
			}
		}
		return openFiles;
	}

	@Override
	public DefaultProjectData getProjectData() {
		return projectData;
	}

	@Override
	public void setSaveableData(String key, SaveState saveState) {
		dataMap.put(key, saveState);
	}

	@Override
	public SaveState getSaveableData(String key) {
		return dataMap.get(key);
	}

	@Override
	public ProjectData getProjectData(ProjectLocator locator) {
		if (locator.equals(projectData.getProjectLocator())) {
			return projectData;
		}

		synchronized (otherViewsMap) {
			for (ProjectData data : otherViewsMap.values()) {
				if (locator.equals(data.getProjectLocator())) {
					return data;
				}
			}
		}

		return null;
	}

	@Override
	public ProjectData[] getViewedProjectData() {
		synchronized (otherViewsMap) {

			// only return visible viewed project
			List<ProjectData> list = new ArrayList<>();
			for (URL url : otherViewsMap.keySet()) {
				if (visibleViews.contains(url)) {
					list.add(otherViewsMap.get(url));
				}
			}

			ProjectData[] veiwedProjectData = new ProjectData[list.size()];
			list.toArray(veiwedProjectData);
			return veiwedProjectData;
		}
	}

	@Override
	public void releaseFiles(Object consumer) {
		projectData.releaseDomainFiles(consumer);
		synchronized (otherViewsMap) {
			for (DefaultProjectData mgr : otherViewsMap.values()) {
				mgr.releaseDomainFiles(consumer);
			}
		}
		TransientDataManager.releaseFiles(consumer);
	}
}
