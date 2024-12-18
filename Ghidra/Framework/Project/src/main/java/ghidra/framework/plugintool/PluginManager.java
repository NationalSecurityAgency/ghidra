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

import java.net.URL;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdom.Element;

import ghidra.framework.main.UtilityPluginPackage;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.mgr.ServiceManager;
import ghidra.framework.plugintool.util.*;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.MultipleCauses;

class PluginManager {
	private static final Logger log = LogManager.getLogger(PluginManager.class);

	private PluginsConfiguration pluginsConfiguration;
	private List<Plugin> pluginList = new ArrayList<>();
	private PluginTool tool;
	private ServiceManager serviceMgr;

	PluginManager(PluginTool tool, ServiceManager serviceMgr,
			PluginsConfiguration pluginsConfiguration) {
		this.tool = tool;
		this.serviceMgr = serviceMgr;
		this.pluginsConfiguration = pluginsConfiguration;
	}

	void installUtilityPlugins() throws PluginException {

		PluginPackage utilityPackage = PluginPackage.getPluginPackage(UtilityPluginPackage.NAME);
		List<PluginDescription> descriptions =
			pluginsConfiguration.getPluginDescriptions(utilityPackage);
		if (descriptions == null) {
			return;
		}

		Set<String> classNames = new HashSet<>();
		for (PluginDescription description : descriptions) {
			String pluginClass = description.getPluginClass().getName();
			classNames.add(pluginClass);
		}

		addPlugins(classNames);
	}

	PluginsConfiguration getPluginsConfiguration() {
		return pluginsConfiguration;
	}

	boolean acceptData(DomainFile[] data) {
		for (Plugin p : pluginList) {
			if (p.acceptData(data)) {
				tool.getWindowManager().getMainWindow().toFront();
				return true;
			}
		}
		return false;
	}

	/**
	 * Identify plugin which will accept specified URL.  If no plugin accepts URL it will be
	 * rejected and false returned. If a plugin can accept the specified URL it will attempt to
	 * process and return true if successful.
	 * The user may be prompted if connecting to the URL requires user authentication.
	 * @param url read-only resource URL
	 * @return true if URL accepted and processed else false
	 */
	boolean accept(URL url) {
		for (Plugin p : pluginList) {
			if (p.accept(url)) {
				tool.getWindowManager().getMainWindow().toFront();
				return true;
			}
		}
		return false;
	}

	void dispose() {
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

	void addPlugins(Collection<String> classNames) throws PluginException {
		PluginException pe = null;
		List<Plugin> list = new ArrayList<>(classNames.size());
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
			for (String className : badList) {
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
		// Delay throwing an exception so we can load the plugins that don't have problems.
		Map<Class<?>, PluginException> dependencyProblemResults = new HashMap<>();
		Set<PluginDependency> unresolvedDependencySet =
			resolveDependencies(dependencyProblemResults);
		if (!unresolvedDependencySet.isEmpty()) {
			for (PluginDependency pd : unresolvedDependencySet) {
				Class<?> dependency = pd.dependency();
				PluginException cause = dependencyProblemResults.get(dependency);
				String dependencyName = dependency.getName();
				String dependentName = pd.dependant().getName();
				String message = """
						Unresolved dependency: %s.  Used by plugin: %s
						""".formatted(dependencyName, dependentName);

				errMsg.append(message).append('\n');
				if (cause != null) {
					errMsg.append("Reason: ").append(cause.getMessage()).append('\n');
				}

				report.addCause(new PluginException(message, cause));
			}
			cleanupPluginsWithUnresolvedDependencies();
		}

		PluginEvent[] lastEvents = tool.getLastEvents();
		List<Plugin> sortedPlugins = getPluginsByServiceOrder(numOldPlugins);
		List<Plugin> badList = new ArrayList<>();
		for (Iterator<Plugin> it = sortedPlugins.iterator(); it.hasNext();) {
			Plugin p = it.next();
			try {
				p.init(); // allow each plugin to acquire services
			}
			catch (Throwable t) {
				Msg.error(this, "Unexpected Exception: " + t.getMessage(), t);
				errMsg.append("Initializing " + p.getName() + " failed: " + t + "\n");
				report.addCause(t);

				// NOTE: other plugins that depend on this failed plugin will still be
				// init()'d as well, which opens a small window of problem causing.
				badList.add(p); // remove plugin from the tool
				it.remove(); // remove the plugin from the iterator so we don't call it later
			}
		}

		if (badList.size() > 0) {
			try {
				removePlugins(badList);
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
	void removePlugins(List<Plugin> plugins) {
		for (Plugin plugin : plugins) {
			unregisterPlugin(plugin);
		}
		cleanupPluginsWithUnresolvedDependencies();
	}

	void saveToXml(Element root, boolean includeConfigState) {

		pluginsConfiguration.savePluginsToXml(root, pluginList);

		if (!includeConfigState) {
			return;
		}

		SaveState saveState = new SaveState("PLUGIN_STATE");
		for (Plugin p : pluginList) {
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
		Collection<String> classNames = isOld ? getPluginClassNamesFromOldXml(root)
				: pluginsConfiguration.getPluginClassNames(root);
		Map<String, SaveState> map = isOld ? getPluginSavedStates(root, "PLUGIN")
				: getPluginSavedStates(root, "PLUGIN_STATE");

		PluginException pe = null;
		try {
			addPlugins(classNames);
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

	private Set<String> getPluginClassNamesFromOldXml(Element root) {
		List<String> classNames = new ArrayList<>();
		List<?> pluginElementList = root.getChildren("PLUGIN");
		Iterator<?> iter = pluginElementList.iterator();
		while (iter.hasNext()) {
			Element elem = (Element) iter.next();
			String className = elem.getAttributeValue("CLASS");
			classNames.add(className);
		}

		return pluginsConfiguration.getPluginNamesByCurrentPackage(classNames);
	}

	private boolean isOldToolConfig(Element root) {
		return root.getChild("PLUGIN") != null;
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
		List<Plugin> plugins = getPluginsByServiceOrder(0);
		for (Plugin p : plugins) {
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
		plugins.forEach(Plugin::dataStateRestoreCompleted);
	}

	Element saveDataStateToXml(boolean savingProject) {
		Element root = new Element("DATA_STATE");
		for (Plugin p : pluginList) {
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

	private Set<PluginDependency> resolveDependencies(
			Map<Class<?>, PluginException> dependencyProblemResults) {

		Set<PluginDependency> dependencies = new HashSet<>();
		do {
			getUnresolvedDependencies(dependencies);
		}
		while (addDependencies(dependencies, dependencyProblemResults));
		return dependencies;
	}

	private void getUnresolvedDependencies(Set<PluginDependency> dependencies) {
		dependencies.clear();
		for (Plugin p : pluginList) {
			List<Class<?>> missingServices = p.getMissingRequiredServices();
			for (Class<?> missingService : missingServices) {
				dependencies.add(new PluginDependency(p.getClass(), missingService));
			}
		}
	}

	/**
	 * @param dependencies set of service interface classes that are required by some plugin
	 * and are not provided by a loaded plugin.
	 * @return boolean true if there was any progress on resolving dependencies, false
	 * if there was no progress or nothing to do.
	 */
	private boolean addDependencies(Set<PluginDependency> dependencies,
			Map<Class<?>, PluginException> dependencyProblemResults) {
		boolean fixedDependency = false;
		for (PluginDependency pd : dependencies) {
			Class<?> dependency = pd.dependency();
			fixedDependency |= fixDependency(dependency, dependencyProblemResults);
		}
		return fixedDependency;
	}

	private Class<? extends Plugin> discoverServiceProvider(Class<?> dependency) {

		Class<? extends Plugin> pluginClass =
			PluginUtils.getDefaultProviderForServiceClass(dependency);
		if (pluginClass != null) {
			return pluginClass;
		}

		//
		// This is searching for any non-loaded Plugin that implements the required service 
		// interface.  Under normal tool configuration, we will not get to this point, since we will
		// have loaded default service providers using the "defaultProvider" annotation attribute.
		// 
		// This code attempts to find the needed plugins by finding service providers that either 
		// implement the service interface or declare that they provide an implementation.
		//
		List<Class<? extends Plugin>> plugins = ClassSearcher.getClasses(Plugin.class)
				.stream()
				.filter(pluginsConfiguration::accepts)
				.collect(Collectors.toList());
		List<Class<? extends Plugin>> serviceProviders = new ArrayList<>();
		for (Class<? extends Plugin> pc : plugins) {

			if (dependency.isAssignableFrom(pc)) {
				serviceProviders.add(pc);
				continue;
			}

			PluginDescription pd = PluginDescription.getPluginDescription(pc);
			List<Class<?>> servicesProvided = pd.getServicesProvided();
			for (Class<?> service : servicesProvided) {
				if (dependency.isAssignableFrom(service)) {
					serviceProviders.add(pc);
				}
			}
		}

		if (serviceProviders.isEmpty()) {
			return null;
		}

		Class<? extends Plugin> choice = serviceProviders.get(0);
		if (serviceProviders.size() != 1) {
			// no choice to be made; just return the only implementation we found
			Msg.warn(this, """
					Unable to find the preferred service provider implementation for %s.
					Picking %s
					""".formatted(dependency.getName(), choice.getName()));
		}

		return choice;
	}

	/**
	 * Tries to find and pull in the plugin that provides a service.
	 *
	 * @param dependency service class that someone depends on
	 * @return boolean true if the dependency was fixed, false if it was not fixed.
	 */
	private boolean fixDependency(Class<?> dependency,
			Map<Class<?>, PluginException> dependencyProblemResults) {

		Class<? extends Plugin> pluginClass = discoverServiceProvider(dependency);
		if (pluginClass == null) {
			return false;
		}

		if (getLoadedPlugin(pluginClass) != null) {
			// This will not typically happen, since a plugin that is already loaded that should 
			// have satisfied the dependency.   This can happen though if the dependency discovery
			// process had to do extra work to find unsatisfied dependencies.
			return true;
		}

		try {
			// Create a new Plugin instance and get its services published.  When its added to the 
			// pluginList, it will be initialized in addPluginInstances() after the 
			// resolveDependencies() and related methods finish.
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
		for (Plugin p : pluginList) {
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
			errMsg.append(e.getClass().getName()).append(": ").append(e.getMessage()).append('\n');
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
		return orderedList;
	}

	/**
	 * Checks to make sure no plugins in the list provide any services used by plugin p.
	 * @param usingPlugin the plugin whose used services should not be provided by any plugins in the list
	 * @param serviceProvidingPlugins the list of plugins that is being tested to see if they provide any
	 * services used by p;
	 * @return true if no plugins in the list provide any services used by p.
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
	 * @param domainObject the domain object
	 * @return true if all the plugins indicated the domain object can close.
	 */
	boolean canCloseDomainObject(DomainObject domainObject) {
		for (Plugin p : pluginList) {
			if (!p.canCloseDomainObject(domainObject)) {
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
	 * @param domainObject the domain object
	 */
	void prepareToSave(DomainObject domainObject) {
		for (Plugin p : pluginList) {
			p.prepareToSave(domainObject);
		}
	}

	private record PluginDependency(Class<?> dependant, Class<?> dependency) {
		// a simple record to tie together a dependant and its required dependency
	}
}
