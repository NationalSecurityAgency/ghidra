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
package ghidra.framework.plugintool;

import java.util.*;
import java.util.Map.Entry;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdom.Element;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.mgr.ServiceManager;
import ghidra.framework.plugintool.util.*;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.MultipleCauses;

class PluginManager {
	static final Logger log = LogManager.getLogger(PluginManager.class);

	private List<Plugin> pluginList = new ArrayList<>();
	private PluginTool tool;
	private ServiceManager serviceMgr;

	PluginManager(PluginTool tool, ServiceManager serviceMgr) {
		this.tool = tool;
		this.serviceMgr = serviceMgr;
	}

	boolean acceptData(DomainFile[] data) {
		for (Plugin p : pluginList) {
			if (p.acceptData(data)) {
				return true;
			}
		}
		return false;
	}

	public void dispose() {
		for (Iterator<Plugin> it = pluginList.iterator(); it.hasNext();) {
			Plugin plugin = it.next();
			plugin.cleanup();
			it.remove();
		}
	}

	DomainFile[] getData() {
		List<DomainFile> list = new ArrayList<>();
		for (Plugin plugin : pluginList) {
			for (DomainFile file : plugin.getData()) {
				list.add(file);
			}
		}
		DomainFile[] data = new DomainFile[list.size()];
		return list.toArray(data);
	}

	Class<?>[] getSupportedDataTypes() {
		Set<Class<?>> set = new HashSet<>();
		for (Plugin plugin : pluginList) {
			for (Class<?> element : plugin.getSupportedDataTypes()) {
				set.add(element);
			}
		}
		Class<?>[] cl = new Class[set.size()];
		return set.toArray(cl);
	}

	void addPlugin(Plugin plugin) throws PluginException {
		addPlugins(new Plugin[] { plugin });
	}

	void addPlugins(String[] classNames) throws PluginException {
		PluginException pe = null;
		List<Plugin> list = new ArrayList<>(classNames.length);
		List<String> badList = new ArrayList<>();
		for (String className : classNames) {
			try {
				Class<? extends Plugin> pluginClass = PluginUtils.forName(className);
				if (getLoadedPlugin(pluginClass) != null) {
					continue;
				}
				PluginUtils.assertUniquePluginName(pluginClass);
				Plugin p = PluginUtils.instantiatePlugin(pluginClass, tool);

				list.add(p);
			}
			catch (PluginException e) {
				pe = e.getPluginException(pe);
				badList.add(className);
			}
		}
		Plugin[] pluginArray = list.toArray(new Plugin[list.size()]);
		try {
			addPlugins(pluginArray);
		}
		catch (PluginException e) {
			pe = e.getPluginException(pe);
		}
		if (badList.size() > 0) {
			//EventManager eventMgr = tool.getEventManager
			for (int i = 0; i < badList.size(); i++) {
				String className = badList.get(i);
				// remove from event manager
				tool.removeEventListener(className);
			}
		}
		if (pe != null) {
			throw pe;
		}
	}

	private <T extends Plugin> T getLoadedPlugin(Class<T> pluginClass) {
		for (Plugin p : pluginList) {
			if (p.getClass() == pluginClass) {
				return pluginClass.cast(p);
			}
		}
		return null;
	}

	private void addPlugins(Plugin[] plugs) throws PluginException {
		serviceMgr.setServiceAddedNotificationsOn(false);

		List<ServiceInterfaceImplementationPair> previousServices = serviceMgr.getAllServices();

		StringBuilder errMsg = new StringBuilder();
		MultipleCauses report = new MultipleCauses();

		int numOldPlugins = pluginList.size();
		for (Plugin newPluginToAdd : plugs) {
			pluginList.add(newPluginToAdd);

			// have each plugin publish its services
			newPluginToAdd.initServices();
		}

		// Find any unresolved dependencies in the plugins we are trying to load.
		// Delay throwing an exception until later so we can load the plugins that don't have problems.
		Map<Class<?>, PluginException> dependencyProblemResults = new HashMap<>();
		Set<Class<?>> unresolvedDependencySet = resolveDependencies(dependencyProblemResults);
		if (!unresolvedDependencySet.isEmpty()) {
			for (Class<?> dependency : unresolvedDependencySet) {
				PluginException cause = dependencyProblemResults.get(dependency);
				errMsg.append("Unresolved dependency: " + dependency.getName() + "\n");
				if (cause != null) {
					errMsg.append("Reason: " + cause.getMessage() + "\n");
				}
				errMsg.append("\n");
				report.addCause(new PluginException("Unresolved dependency: " + dependency, cause));
			}
			cleanupPluginsWithUnresolvedDependencies();
		}

		PluginEvent[] lastEvents = tool.getLastEvents();
		List<Plugin> sortedPlugins = getPluginsByServiceOrder(numOldPlugins);
		List<Plugin> badList = new ArrayList<>();
		for (Iterator<Plugin> it = sortedPlugins.iterator(); it.hasNext();) {
			Plugin p = it.next();
			try {
				// allow each plugin to acquire services
				p.init();
			}
			catch (Throwable t) {
				Msg.error(this, "Unexpected Exception: " + t.getMessage(), t);
				errMsg.append("Initializing " + p.getName() + " failed: " + t + "\n");
				report.addCause(t);

				badList.add(p); // remove plugin from the tool
				it.remove(); // remove the plugin from the iterator so we don't call it later
				// NOTE: other plugins that depend on this failed plugin will still be
				// init()'d as well, which opens a small window of problem causing.
			}
		}

		if (badList.size() > 0) {
			Plugin[] badPlugins = new Plugin[badList.size()];
			try {
				removePlugins(badList.toArray(badPlugins));
			}
			catch (Throwable t) {
				log.debug("Exception unloading plugin", t);
			}
		}
		serviceMgr.setServiceAddedNotificationsOn(true);

		// notify the new plugins of all pre-existing services.
		for (Plugin p : sortedPlugins) {
			notifyServices(p, previousServices);
		}

		for (Plugin p : sortedPlugins) {
			p.processLastEvents(lastEvents);
		}
		if (errMsg.length() > 0) {
			throw new PluginException(errMsg.toString(), report);
		}
	}

	private void notifyServices(Plugin p,
			List<ServiceInterfaceImplementationPair> previousServices) {
		for (ServiceInterfaceImplementationPair service : previousServices) {
			p.serviceAdded(service.interfaceClass, service.provider);
		}
	}

	List<Plugin> getPlugins() {
		return new ArrayList<>(pluginList);
	}

	/**
	 * Removes the given plugins from the tool and removes any other plugins that were
	 * depending on them.
	 * @param plugins the list of plugins to remove.
	 */
	void removePlugins(Plugin[] plugins) {
		for (Plugin plugin : plugins) {
			unregisterPlugin(plugin);
		}
		cleanupPluginsWithUnresolvedDependencies();
	}

	void saveToXml(Element root, boolean includeConfigState) {
		PluginClassManager pluginClassManager = tool.getPluginClassManager();
		pluginClassManager.addXmlElementsForPlugins(root, pluginList);

		if (!includeConfigState) {
			return;
		}

		SaveState saveState = new SaveState("PLUGIN_STATE");

		Iterator<Plugin> it = pluginList.iterator();
		while (it.hasNext()) {
			Plugin p = it.next();
			p.writeConfigState(saveState);
			if (!saveState.isEmpty()) {
				Element pluginElem = saveState.saveToXml();
				pluginElem.setAttribute("CLASS", p.getClass().getName());
				root.addContent(pluginElem);
				saveState = new SaveState("PLUGIN_STATE");
			}
		}
	}

	void restorePluginsFromXml(Element root) throws PluginException {
		boolean isOld = isOldToolConfig(root);
		List<String> classNames =
			isOld ? getPLuginClassNamesFromOldXml(root) : getPluginClassNamesToLoad(root);
		Map<String, SaveState> map = isOld ? getPluginSavedStates(root, "PLUGIN")
				: getPluginSavedStates(root, "PLUGIN_STATE");

		PluginException pe = null;
		try {
			addPlugins(classNames.toArray(new String[classNames.size()]));
		}
		catch (PluginException e) {
			pe = e;
		}

		try {
			initConfigStates(map);
		}
		catch (PluginException e) {
			pe = e.getPluginException(pe);
		}
		if (pe != null) {
			throw pe;
		}

	}

	private Map<String, SaveState> getPluginSavedStates(Element root, String elementName) {
		Map<String, SaveState> map = new HashMap<>();
		List<?> children = root.getChildren(elementName);
		for (Object object : children) {
			Element child = (Element) object;
			String className = child.getAttributeValue("CLASS");
			map.put(className, new SaveState(child));
		}
		return map;
	}

	private List<String> getPLuginClassNamesFromOldXml(Element root) {
		List<String> classNames = new ArrayList<>();
		List<?> pluginElementList = root.getChildren("PLUGIN");
		Iterator<?> iter = pluginElementList.iterator();
		while (iter.hasNext()) {
			Element elem = (Element) iter.next();
			String className = elem.getAttributeValue("CLASS");
			classNames.add(className);
		}
		PluginClassManager pluginClassManager = tool.getPluginClassManager();
		return pluginClassManager.fillInPackageClasses(classNames);
	}

	private boolean isOldToolConfig(Element root) {
		return root.getChild("PLUGIN") != null;
	}

	private List<String> getPluginClassNamesToLoad(Element root) {
		PluginClassManager pluginClassManager = tool.getPluginClassManager();
		return pluginClassManager.getPluginClasses(root);
	}

	/**
	 * Restore the data state from the given XML element.
	 * @param root XML element containing plugins' data state
	 */
	void restoreDataStateFromXml(Element root) {
		Map<String, SaveState> map = new HashMap<>();
		Iterator<?> iter = root.getChildren("PLUGIN").iterator();
		while (iter.hasNext()) {
			Element elem = (Element) iter.next();
			String pluginName = elem.getAttributeValue("NAME");

			SaveState saveState = new SaveState(elem);
			map.put(pluginName, saveState);
		}

		Map<String, Exception> badMap = new LinkedHashMap<>();
		List<Plugin> list = getPluginsByServiceOrder(0);
		for (Plugin p : list) {
			SaveState saveState = map.get(p.getName());
			if (saveState != null) {
				try {
					p.readDataState(saveState);
				}
				catch (Exception e) {
					badMap.put(p.getName(), e);
				}
			}
		}
		if (badMap.size() > 0) {
			log.error("*** Errors in Plugin Data States  ***");
			log.error("The data states for following plugins could not be restored:");
			Set<Entry<String, Exception>> entrySet = badMap.entrySet();
			for (Entry<String, Exception> entry : entrySet) {
				String pluginName = entry.getKey();
				Exception exception = entry.getValue();
				log.error("     " + pluginName, exception);
			}
			log.error("*** (finished) Errors in Plugin Data States  ***");
			Msg.showError(this, null, "Data State Error",
				"Errors in plugin data states - check console for details");
		}
		for (Plugin plugin : list) {
			plugin.dataStateRestoreCompleted();
		}
	}

	Element saveDataStateToXml(boolean savingProject) {
		Element root = new Element("DATA_STATE");
		for (int i = 0; i < pluginList.size(); i++) {
			Plugin p = pluginList.get(i);
			SaveState ss = new SaveState("PLUGIN");
			p.writeDataState(ss);
			if (!ss.isEmpty()) {
				Element e = ss.saveToXml();
				e.setAttribute("NAME", p.getName());
				root.addContent(e);
			}
		}
		return root;
	}

	private void unregisterPlugin(Plugin plugin) {
		if (pluginList.remove(plugin)) {
			plugin.cleanup();
			tool.getOptionsManager().deregisterOwner(plugin);
		}
	}

	private void cleanupPluginsWithUnresolvedDependencies() {
		Plugin p;
		while ((p = findPluginWithUnresolvedDependencies()) != null) {
			unregisterPlugin(p);
		}
	}

	private Plugin findPluginWithUnresolvedDependencies() {
		for (Plugin plugin : pluginList) {
			if (plugin.hasMissingRequiredService()) {
				return plugin;
			}
		}
		return null;
	}

	private Set<Class<?>> resolveDependencies(
			Map<Class<?>, PluginException> dependencyProblemResults) {
		Set<Class<?>> dependencySet = new HashSet<>();
		do {
			getUnresolvedDependencies(dependencySet, dependencyProblemResults);
		}
		while (addDependencies(dependencySet, dependencyProblemResults));
		return dependencySet;
	}

	private void getUnresolvedDependencies(Set<Class<?>> dependencySet,
			Map<Class<?>, PluginException> dependencyProblemResults) {
		dependencySet.clear();
		for (Plugin p : pluginList) {
			dependencySet.addAll(p.getMissingRequiredServices());
		}
	}

	/**
	 * @param dependencySet set of service interface classes that are required by some plugin
	 * and are not provided by a loaded plugin.
	 * @return boolean true if there was any progress on resolving dependencies, false
	 * if there was no progress or nothing to do.
	 */
	private boolean addDependencies(Set<Class<?>> dependencySet,
			Map<Class<?>, PluginException> dependencyProblemResults) {
		boolean fixedDependency = false;
		for (Class<?> depClass : dependencySet) {
			fixedDependency |= fixDependency(depClass, dependencyProblemResults);
		}
		return fixedDependency;
	}

	/**
	 * Tries to find and pull in the plugin that provides a service.
	 *
	 * @param dependency service class that someone depends on
	 * @return boolean true if the dependency was fixed, false if it was not fixed.
	 */
	private boolean fixDependency(Class<?> dependency,
			Map<Class<?>, PluginException> dependencyProblemResults) {
		Class<? extends Plugin> pluginClass =
			PluginUtils.getDefaultProviderForServiceClass(dependency);
		if (pluginClass == null) {
			// TODO: this following loop is searching for any non-loaded Plugin that implements
			// the required service class interface.
			// This doesn't seem exactly right as a Service implementation shouldn't
			// be automagically pulled in and instantiated UNLESS it was specified as the "defaultProvider",
			// which we've already checked for in the previous PluginUtils.getDefaultProviderForServiceClass().
			// TODO: this also should be filtered by the PluginClassManager so we don't
			// pull in classes that have been excluded.
			for (Class<? extends Plugin> pc : ClassSearcher.getClasses(Plugin.class)) {
				if (dependency.isAssignableFrom(pc)) {
					pluginClass = pc;
					break;
				}
			}
		}
		if (pluginClass == null) {
			return false;
		}

		if (getLoadedPlugin(pluginClass) != null) {
			// This should not happen and means that our world view is corrupted.
			// A plugin that is already loaded that should have satisfied the dependency
			// for some reason didn't.
			// Warn about the situation and don't try to create another instance of this plugin.
			Msg.warn(this,
				"Plugin " + pluginClass.getSimpleName() + " provides service " +
					dependency.getSimpleName() +
					" but that dependency failed to be resolved correctly in a previous step.");
			return true;
		}

		try {
			// create a new Plugin instance and get its services published.
			// when its added to the pluginList, it will be initialized in
			// addPluginInstances() after the resolveDependencies() and related methods finish.
			PluginUtils.assertUniquePluginName(pluginClass);
			Plugin p = PluginUtils.instantiatePlugin(pluginClass, tool);

			p.initServices();

			pluginList.add(p);
			return true;
		}
		catch (PluginException e) {
			dependencyProblemResults.put(dependency, e);
		}
		return false;
	}

	private void initConfigStates(Map<String, SaveState> map) throws PluginException {
		StringBuilder errMsg = new StringBuilder();
		Iterator<Plugin> it = pluginList.iterator();
		while (it.hasNext()) {
			Plugin p = it.next();
			readSaveState(p, map, errMsg);
		}
		if (errMsg.length() > 0) {
			throw new PluginException(errMsg.toString());
		}
	}

	private void readSaveState(Plugin p, Map<String, SaveState> map, StringBuilder errMsg) {
		SaveState ss = map.get(p.getClass().getName());
		if (ss == null) {
			return;
		}

		try {
			p.readConfigState(ss);
		}
		catch (Exception e) {
			errMsg.append("Problem restoring plugin state for: " + p.getName()).append("\n\n");
			errMsg.append(e.getClass().getName())
					.append(": ")
					.append(e.getMessage())
					.append('\n');
			StackTraceElement[] st = e.getStackTrace();
			int depth = Math.min(5, st.length); // only show the important stuff (magic guess)
			for (int j = 0; j < depth; j++) {
				errMsg.append("    ").append(st[j].toString()).append('\n');
			}
			errMsg.append('\n'); // extra break between this and future messages
		}
	}

	private List<Plugin> getPluginsByServiceOrder(int startIndex) {
		List<Plugin> plugins = new ArrayList<>(pluginList.subList(startIndex, pluginList.size()));
		List<Plugin> orderedList = new ArrayList<>(plugins.size());
//		showList("Before:", pluginList);
		while (plugins.size() > 0) {
			int n = plugins.size();
			for (Iterator<Plugin> it = plugins.iterator(); it.hasNext();) {
				Plugin p = it.next();
				if (checkServices(p, plugins)) {
					orderedList.add(p);
					it.remove();
				}
			}
			if (n == plugins.size()) {
				showWarning(plugins);
				orderedList.addAll(plugins);
				plugins.clear();
			}
		}
//		showList("After:",orderedList);
		return orderedList;
	}

//	private void showList(String title, ArrayList list) {
//		Err.debug(this, title);
//		Iterator it = list.iterator();
//		while(it.hasNext()) {
//			Plugin p = (Plugin)it.next();
//			Err.debug(this, "   "+p.getName());
//		}
//	}

	/**
	 * Checks to make sure no plugins in the list provide any services used by plugin p.
	 * @param usingPlugin the plugin whose used services should not be provided by any plugins in the list
	 * @param serviceProvidingPlugins the list of plugins that is being tested to see if they provide any
	 * services used by p;
	 * @return true if no plugins in the the list provide any services used by p.
	 */
	private boolean checkServices(Plugin usingPlugin, List<Plugin> serviceProvidingPlugins) {
		for (Class<?> usedService : usingPlugin.getServicesRequired()) {
			for (Plugin providingPlugin : serviceProvidingPlugins) {
				if (providingPlugin.providesService(usedService)) {
					return false;
				}
			}
		}
		return true;
	}

	private void showWarning(List<Plugin> plugins) {
		Msg.warn(this, "The correct order for initializing the following plugins can't be\n" +
			"determined because of circular use of services (check log)");
		for (Plugin plugin : plugins) {
			Msg.info(this, "Plugin: " + plugin.getClass().getName());
			for (Class<?> service : plugin.getServiceClasses()) {
				Msg.info(this, "    provides: " + service);
			}
			for (Class<?> usedService : plugin.getServicesRequired()) {
				Msg.info(this, "    uses: " + usedService);
			}
		}
	}

	/**
	 * Called to force plugins to terminate any tasks they has running and
	 * apply any unsaved data to domain objects or files. If they can't do
	 * this or the user cancels then this returns false.
	 * @return true if all the plugins indicated they can close.
	 */
	boolean canClose() {
		for (Plugin p : pluginList) {
			if (!p.canClose()) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Allow plugins to cancel the closing of the domain object.
	 * Note: This forces plugins to terminate any tasks they have running for the
	 * indicated domain object and apply any unsaved data to the domain object. If they can't do
	 * this or the user cancels then this returns false.
	 * @return true if all the plugins indicated the domain object can close.
	 */
	boolean canCloseDomainObject(DomainObject dObj) {
		for (Plugin p : pluginList) {
			if (!p.canCloseDomainObject(dObj)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Called to force plugins to save any domain object data it is controlling.
	 * @return false if a domain object related plugin couldn't save its data.
	 */
	boolean saveData() {
		for (Plugin p : pluginList) {
			if (!p.saveData()) {
				return false;
			}
		}
		return true;
	}

	boolean hasUnsavedData() {
		for (Plugin p : pluginList) {
			if (p.hasUnsaveData()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Close all the plugins.
	 */
	void close() {
		for (Plugin p : pluginList) {
			p.close();
		}
	}

	public TransientToolState getTransientState() {
		return new TransientToolState(new ArrayList<>(pluginList));
	}

	public UndoRedoToolState getUndoRedoToolState(DomainObject domainObject) {
		return new UndoRedoToolState(new ArrayList<>(pluginList), domainObject);
	}

	/**
	 * Notify plugins that the domain object is about to be saved.
	 */
	void prepareToSave(DomainObject dObj) {
		for (Plugin p : pluginList) {
			p.prepareToSave(dObj);
		}
	}

}
