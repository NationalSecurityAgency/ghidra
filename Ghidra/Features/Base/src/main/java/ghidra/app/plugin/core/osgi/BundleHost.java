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
package ghidra.app.plugin.core.osgi;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.felix.framework.FrameworkFactory;
import org.apache.felix.framework.util.FelixConstants;
import org.osgi.framework.*;
import org.osgi.framework.launch.Framework;
import org.osgi.framework.wiring.*;

import generic.io.NullPrintWriter;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * Hosts the embedded OSGi framework and manages {@link GhidraBundle}s.
 * 
 * <br/><br/>
 * note: {@link GhidraBundle}, its implementations, and this class constitute 
 * a bridge between OSGi's {@link Bundle} and Ghidra.
 * <ul>
 * <li> unqualified, "bundle" will mean {@link GhidraBundle}
 * <li> use of OSGi types, including {@link Bundle} and {@link Framework}, should be package 
 * scoped (not public)  
 * <li> bundle lifecycle is simplified to "active"(same as OSGi "active" state)
 * and "inactive" (OSGi "uninstalled" state)
 * </ul>
 */
public class BundleHost {
	protected static final boolean STDERR_DEBUGGING = false;
	private static final String SAVE_STATE_TAG_FILE = "BundleHost_FILE";
	private static final String SAVE_STATE_TAG_ENABLE = "BundleHost_ENABLE";
	private static final String SAVE_STATE_TAG_ACTIVE = "BundleHost_ACTIVE";
	private static final String SAVE_STATE_TAG_SYSTEM = "BundleHost_SYSTEM";

	Map<ResourceFile, GhidraBundle> fileToBundleMap = new HashMap<>();
	Map<String, GhidraBundle> bundleLocationToBundleMap = new HashMap<>();

	BundleContext frameworkBundleContext;
	Framework felixFramework;

	List<BundleHostListener> listeners = new CopyOnWriteArrayList<>();

	/** constructor */
	public BundleHost() {
		//
	}

	/**
	 * stop the framework.
	 */
	public void dispose() {
		stopFramework();
	}

	/**
	 * If a {@link GhidraBundle} hasn't already been added for {@bundleFile}, add it now as a 
	 * non-system bundle.
	 * 
	 * <p>Enable the bundle.
	 * 
	 * @param bundleFile the bundle file to (add and) enable
	 * @return false if the bundle was already enabled
	 */
	public boolean enable(ResourceFile bundleFile) {
		GhidraBundle bundle = fileToBundleMap.get(bundleFile);
		if (bundle == null) {
			bundle = add(bundleFile, true, false);
			return true;
		}
		return enable(bundle);
	}

	/**
	 * Enable a bundle and notify listeners.
	 * 
	 * @param bundle the bundle to enable
	 * @return false if the bundle was already enabled
	 */
	public boolean enable(GhidraBundle bundle) {
		if (!bundle.isEnabled()) {
			bundle.setEnabled(true);
			fireBundleEnablementChange(bundle, true);
			return true;
		}
		return false;
	}

	/**
	 * Disable a bundle and notify listeners.
	 * 
	 * @param bundle the bundle to disable
	 * @return true if the bundle was enabled
	 */
	public boolean disable(GhidraBundle bundle) {
		if (bundle.isEnabled()) {
			bundle.setEnabled(false);
			fireBundleEnablementChange(bundle, false);
			return true;
		}
		return false;
	}

	/**
	 * If there is currently a bundle managed with file {@code bundleFile},
	 * return its {@link GhidraBundle}, otherwise return {@code null}. 
	 * 
	 * @param bundleFile the bundleFile of the sought bundle
	 * @return a {@link GhidraBundle} or {@code null}
	 */
	public GhidraBundle getExistingGhidraBundle(ResourceFile bundleFile) {
		GhidraBundle bundle = fileToBundleMap.get(bundleFile);
		if (bundle == null) {
			Msg.showError(this, null, "ghidra bundle cache",
				"getExistingGhidraBundle expected a GhidraBundle created at " + bundleFile +
					" but none was found");
		}
		return bundle;
	}

	private static GhidraBundle createGhidraBundle(BundleHost bundleHost, ResourceFile bundleFile,
			boolean enabled, boolean systemBundle) {
		if (!bundleFile.exists()) {
			return new GhidraPlaceholderBundle(bundleHost, bundleFile, enabled, systemBundle,
				"file not found: " + generic.util.Path.toPathString(bundleFile));
		}

		switch (GhidraBundle.getType(bundleFile)) {
			case SOURCE_DIR:
				return new GhidraSourceBundle(bundleHost, bundleFile, enabled, systemBundle);
			case JAR:
				return new GhidraJarBundle(bundleHost, bundleFile, enabled, systemBundle);
			case BND_SCRIPT:
			default:
				break;
		}
		return new GhidraPlaceholderBundle(bundleHost, bundleFile, enabled, systemBundle,
			"no bundle type for " + generic.util.Path.toPathString(bundleFile));
	}

	/**
	 * Create a new GhidraBundle and add to the list of managed bundles
	 * 
	 * @param bundleFile the bundle file
	 * @param enabled if the new bundle should be enabled
	 * @param systemBundle if the new bundle is a system bundle
	 * @return a new GhidraBundle
	 */
	public GhidraBundle add(ResourceFile bundleFile, boolean enabled, boolean systemBundle) {
		GhidraBundle bundle = createGhidraBundle(this, bundleFile, enabled, systemBundle);
		fileToBundleMap.put(bundleFile, bundle);
		bundleLocationToBundleMap.put(bundle.getLocationIdentifier(), bundle);
		fireBundleAdded(bundle);
		return bundle;
	}

	/**
	 * Create new GhidraBundles and add to the list of managed bundles.  All GhidraBundles created 
	 * with the same {@code enabled} and {@code systemBundle} values. 
	 * 
	 * @param bundleFiles a list of bundle files
	 * @param enabled if the new bundle should be enabled
	 * @param systemBundle if the new bundle is a system bundle
	 * @return the new bundle objects
	 */
	public Collection<GhidraBundle> add(List<ResourceFile> bundleFiles, boolean enabled,
			boolean systemBundle) {
		Map<ResourceFile, GhidraBundle> newBundleMap = bundleFiles.stream()
				.collect(Collectors.toUnmodifiableMap(Function.identity(),
					bundleFile -> createGhidraBundle(BundleHost.this, bundleFile, enabled,
						systemBundle)));
		fileToBundleMap.putAll(newBundleMap);
		bundleLocationToBundleMap.putAll(newBundleMap.values()
				.stream()
				.collect(Collectors.toUnmodifiableMap(GhidraBundle::getLocationIdentifier,
					Function.identity())));
		Collection<GhidraBundle> newBundles = newBundleMap.values();
		fireBundlesAdded(newBundles);
		return newBundles;
	}

	/**
	 * Add bundles to the list of managed bundles.
	 * 
	 * @param bundles the bundles to add
	 */
	private void add(List<GhidraBundle> bundles) {
		for (GhidraBundle bundle : bundles) {
			fileToBundleMap.put(bundle.getFile(), bundle);
			bundleLocationToBundleMap.put(bundle.getLocationIdentifier(), bundle);
		}
		fireBundlesAdded(bundles);
	}

	/**
	 * Remove a bundle from the list of managed bundles.
	 * 
	 * @param bundleFile the file of the bundle to remove
	 */
	public void remove(ResourceFile bundleFile) {
		GhidraBundle bundle = fileToBundleMap.remove(bundleFile);
		bundleLocationToBundleMap.remove(bundle.getLocationIdentifier());
		fireBundleRemoved(bundle);
	}

	/**
	 * Remove a bundle from the list of managed bundles.
	 * 
	 * @param bundleLocation the location id of the bundle to remove
	 */
	public void remove(String bundleLocation) {
		GhidraBundle bundle = bundleLocationToBundleMap.remove(bundleLocation);
		fileToBundleMap.remove(bundle.getFile());
		fireBundleRemoved(bundle);
	}

	/**
	 * Remove a bundle from the list of managed bundles.
	 * 
	 * @param bundle the bundle to remove
	 */
	public void remove(GhidraBundle bundle) {
		fileToBundleMap.remove(bundle.getFile());
		bundleLocationToBundleMap.remove(bundle.getLocationIdentifier());
		fireBundleRemoved(bundle);
	}

	/**
	 * Remove bundles from the list of managed bundles.
	 * 
	 * @param bundles the bundles to remove
	 */
	public void remove(Collection<GhidraBundle> bundles) {
		for (GhidraBundle bundle : bundles) {
			fileToBundleMap.remove(bundle.getFile());
			bundleLocationToBundleMap.remove(bundle.getLocationIdentifier());
		}
		fireBundlesRemoved(bundles);
	}

	Bundle installFromPath(Path p) throws GhidraBundleException {
		return installFromLoc("file://" + p.toAbsolutePath().normalize().toString());
	}

	/**
	 * Try to install a bundle.
	 * 
	 * @param bundle the bundle to install
	 * @return the OSGi bundle returned by the framework
	 * @throws GhidraBundleException if install fails
	 */
	public Bundle install(GhidraBundle bundle) throws GhidraBundleException {
		try {
			return frameworkBundleContext.installBundle(bundle.getLocationIdentifier());
		}
		catch (BundleException e) {
			throw new GhidraBundleException(bundle.getLocationIdentifier(),
				"installing from bundle location", e);
		}
	}

	Bundle installFromLoc(String bundleLocation) throws GhidraBundleException {
		try {
			return frameworkBundleContext.installBundle(bundleLocation);
		}
		catch (BundleException e) {
			throw new GhidraBundleException(bundleLocation, "installing from bundle location", e);
		}
	}

	Bundle installAsLoc(String bundleLocation, InputStream contents) throws GhidraBundleException {
		try {
			return frameworkBundleContext.installBundle(bundleLocation, contents);
		}
		catch (BundleException e) {
			throw new GhidraBundleException(bundleLocation, "installing as bundle location", e);
		}
	}

	/** 
	 * return all of the currently managed bundles
	 *  
	 * @return all the bundles
	 */
	public Collection<GhidraBundle> getGhidraBundles() {
		return fileToBundleMap.values();
	}

	/**
	 * return the list of currently managed bundle files
	 * 
	 * @return all the bundle files
	 */
	public Collection<ResourceFile> getBundleFiles() {
		return fileToBundleMap.keySet();
	}

	void dumpLoadedBundles() {
		System.err.printf("=== Bundles ===\n");
		for (Bundle bundle : frameworkBundleContext.getBundles()) {
			System.err.printf("%s: %s: %s: %s\n", bundle.getBundleId(), bundle.getSymbolicName(),
				bundle.getState(), bundle.getVersion());
		}
	}

	/**
	 * Attempt to resolve a list of BundleRequirements with active Bundle capabilities.
	 * 
	 * @param requirements list of requirements -- satisfied requirements are removed as 
	 * capabilities are found
	 * @return list of {@link BundleWiring} objects corresponding to matching capabilities
	 */
	public List<BundleWiring> resolve(List<BundleRequirement> requirements) {
		// enumerate active bundles, looking for capabilities meeting our requirements
		List<BundleWiring> bundleWirings = new ArrayList<>();
		for (Bundle bundle : frameworkBundleContext.getBundles()) {
			if (bundle.getState() == Bundle.ACTIVE) {
				BundleWiring bundleWiring = bundle.adapt(BundleWiring.class);
				boolean keeper = false;
				for (BundleCapability capability : bundleWiring.getCapabilities(null)) {
					Iterator<BundleRequirement> requirementsIterator = requirements.iterator();
					while (requirementsIterator.hasNext()) {
						BundleRequirement requirement = requirementsIterator.next();
						if (requirement.matches(capability)) {
							requirementsIterator.remove();
							keeper = true;
						}
					}
				}
				if (keeper) {
					bundleWirings.add(bundleWiring);
				}
			}
		}
		return bundleWirings;
	}

	/**
	 * Attempt to resolve {@code requirements} against the currently active bundles.
	 * 
	 * @param requirements a list of {@link BundleRequirement} objects
	 * @return true if all of the requirements can be resolved
	 */
	public boolean canResolveAll(Collection<BundleRequirement> requirements) {
		LinkedList<BundleRequirement> tmpRequirements = new LinkedList<>(requirements);
		resolve(tmpRequirements);
		return tmpRequirements.isEmpty();
	}

	protected String buildExtraSystemPackages() {
		Set<String> packages = new HashSet<>();
		OSGiUtils.getPackagesFromClasspath(packages);
		return packages.stream().collect(Collectors.joining(","));
	}

	/**
	 * A subdirectory of the user settings directory for storing OSGi artifacts.
	 * 
	 * @return the path
	 */
	public static Path getOsgiDir() {
		Path usersettings = Application.getUserSettingsDirectory().toPath();
		return usersettings.resolve("osgi");
	}

	/**
	 * A directory for use by the OSGi framework as a cache
	 * 
	 * @return the directory
	 */
	protected static Path getCacheDir() {
		return BundleHost.getOsgiDir().resolve("felixcache");
	}

	private static String makeCacheDir() throws IOException {
		Path cacheDir = getCacheDir();
		Files.createDirectories(cacheDir);
		return cacheDir.toAbsolutePath().toString();
	}

	protected void createAndConfigureFramework() throws IOException {
		Properties config = new Properties();

		// allow multiple bundles w/ the same symbolic name -- location can distinguish
		config.setProperty(Constants.FRAMEWORK_BSNVERSION, Constants.FRAMEWORK_BSNVERSION_MULTIPLE);
		// use the default, inferred from environment
		// config.setProperty(Constants.FRAMEWORK_SYSTEMCAPABILITIES,"osgi.ee; osgi.ee=\"JavaSE\";version:List=\"...\"");

		// compute and add everything in the class path.  extra packages have lower precedence than imports,
		// so an Import-Package / @importpackage will override the "living off the land" default
		config.setProperty(Constants.FRAMEWORK_SYSTEMPACKAGES_EXTRA, buildExtraSystemPackages());

		// only clean on first startup, o/w keep our storage around
		config.setProperty(Constants.FRAMEWORK_STORAGE_CLEAN,
			Constants.FRAMEWORK_STORAGE_CLEAN_ONFIRSTINIT);

		// setup the cache path
		config.setProperty(Constants.FRAMEWORK_STORAGE, makeCacheDir());

		config.put(FelixConstants.LOG_LEVEL_PROP, "1");
		if (STDERR_DEBUGGING) {
			config.put(FelixConstants.LOG_LEVEL_PROP, "999");
			// config.put(FelixConstants.LOG_LOGGER_PROP, new org.apache.felix.framework.Logger() {...});
		}

		FrameworkFactory factory = new FrameworkFactory();
		felixFramework = factory.newFramework(config);
	}

	protected void addDebuggingListeners() {
		frameworkBundleContext.addFrameworkListener(new FrameworkListener() {
			@Override
			public void frameworkEvent(FrameworkEvent event) {
				System.err.printf("%s %s\n", event.getBundle(), event);
			}
		});
		frameworkBundleContext.addServiceListener(new ServiceListener() {
			@Override
			public void serviceChanged(ServiceEvent event) {

				String type = "?";
				if (event.getType() == ServiceEvent.REGISTERED) {
					type = "registered";
				}
				else if (event.getType() == ServiceEvent.UNREGISTERING) {
					type = "unregistering";
				}

				System.err.printf("%s %s from %s\n", event.getSource(), type,
					event.getServiceReference().getBundle().getLocation());

			}
		});
	}

	/**
	 * start the framework
	 * 
	 * @throws OSGiException framework failures
	 * @throws IOException filesystem setup
	 */
	public void startFramework() throws OSGiException, IOException {
		createAndConfigureFramework();

		try {
			felixFramework.init();
		}
		catch (BundleException e) {
			throw new OSGiException("initializing felix OSGi framework", e);
		}
		frameworkBundleContext = felixFramework.getBundleContext();

		if (STDERR_DEBUGGING) {
			addDebuggingListeners();
		}

		frameworkBundleContext
				.addBundleListener(new MyBundleListener(frameworkBundleContext.getBundle()));

		try {
			felixFramework.start();
		}
		catch (BundleException e) {
			throw new OSGiException("starting felix OSGi framework", e);
		}
	}

	/**
	 * stop the OSGi framework synchronously
	 */
	protected void stopFramework() {
		if (felixFramework != null) {
			try {
				felixFramework.stop();
				// any bundles that linger after a few seconds might be the source
				// of subtle problems, so wait for them to stop and report any problems.
				FrameworkEvent event = felixFramework.waitForStop(5000);
				if (event.getType() == FrameworkEvent.WAIT_TIMEDOUT) {
					Msg.error(this, "Stopping OSGi framework timed out after 5 seconds.");
				}
				felixFramework = null;
			}
			catch (BundleException | InterruptedException e) {
				Msg.error(this, "Failed to stop OSGi framework.");
				e.printStackTrace();
			}
		}
	}

	/**
	 * @return the OSGi framework
	 */
	Framework getHostFramework() {
		return felixFramework;
	}

	/**
	 * Get the OSGi bundle with the given bundle location identifier.
	 * 
	 * @param bundleLocation the bundle location identifier
	 * @return the OSGi bundle or null
	 */
	Bundle getOSGiBundle(String bundleLocation) {
		return frameworkBundleContext.getBundle(bundleLocation);
	}

	/**
	 * Activate a bundle. Either an exception is thrown or the bundle will be in "ACTIVE" state.
	 * 
	 * @param bundle the bundle
	 * @throws GhidraBundleException if there's a problem activating
	 */
	public void activateSynchronously(Bundle bundle) throws GhidraBundleException {
		if (bundle.getState() == Bundle.ACTIVE) {
			return;
		}
		try {
			bundle.start();
		}
		catch (BundleException e) {
			GhidraBundleException bundleException =
				new GhidraBundleException(bundle, "activating bundle", e);
			fireBundleException(bundleException);
			throw bundleException;
		}
	}

	/**
	 * Activate a bundle. Either an exception is thrown or the bundle will be in "ACTIVE" state.
	 * 
	 * @param bundleLocation the bundle location identifier
	 * @throws InterruptedException if the wait is interrupted
	 * @throws GhidraBundleException if there's a problem activating
	 */
	public void activateSynchronously(String bundleLocation)
			throws GhidraBundleException, InterruptedException {
		Bundle bundle = getOSGiBundle(bundleLocation);
		if (bundle == null) {
			bundle = installFromLoc(bundleLocation);
		}
		activateSynchronously(bundle);
	}

	/**
	 * Deactivate a bundle. Either an exception is thrown or the bundle will be in "UNINSTALLED" state.
	 * 
	 * @param bundle the bundle
	 * @throws GhidraBundleException if there's a problem activating
	 */
	public void deactivateSynchronously(Bundle bundle) throws GhidraBundleException {
		if (bundle.getState() == Bundle.UNINSTALLED) {
			return;
		}
		FrameworkWiring frameworkWiring = felixFramework.adapt(FrameworkWiring.class);
		LinkedList<Bundle> dependentBundles = new LinkedList<Bundle>(
			frameworkWiring.getDependencyClosure(Collections.singleton(bundle)));
		while (!dependentBundles.isEmpty()) {
			Bundle dependentBundle = dependentBundles.pop();
			try {
				dependentBundle.uninstall();
				if (dependentBundle.getState() != Bundle.UNINSTALLED) {
					Msg.error(this, "Failed to uninstall bundle: " + dependentBundle.getLocation());
				}
				refreshBundlesSynchronously(new ArrayList<>(dependentBundles));
			}
			catch (BundleException e) {
				GhidraBundleException exception =
					new GhidraBundleException(dependentBundle, "deactivating bundle", e);
				fireBundleException(exception);
				throw exception;
			}
		}
	}

	/**
	 * Deactivate a bundle. Either an exception is thrown or the bundle will be in "UNINSTALLED" state.
	 * 
	 * @param bundleLocation the bundle location identifier
	 * @throws InterruptedException if the wait is interrupted
	 * @throws GhidraBundleException if there's a problem activating
	 */
	public void deactivateSynchronously(String bundleLocation)
			throws GhidraBundleException, InterruptedException {
		Bundle bundle = getOSGiBundle(bundleLocation);
		if (bundle != null) {
			deactivateSynchronously(bundle);
		}
	}

	/**
	 * Refreshes the specified bundles. This forces the update (replacement) 
	 * or removal of packages exported by the specified bundles.
	 * 
	 * @param bundles the bundles to refresh
	 * @see FrameworkWiring#refreshBundles
	 */
	protected void refreshBundlesSynchronously(Collection<Bundle> bundles) {
		FrameworkWiring frameworkWiring = felixFramework.adapt(FrameworkWiring.class);
		final CountDownLatch latch = new CountDownLatch(1);
		frameworkWiring.refreshBundles(bundles, new FrameworkListener() {
			@Override
			public void frameworkEvent(FrameworkEvent event) {
				if (event.getType() == FrameworkEvent.ERROR) {
					Bundle bundle = event.getBundle();
					Msg.error(BundleHost.this,
						String.format("OSGi error refreshing bundle: %s", bundle));
				}
				latch.countDown();
			}
		});
		try {
			latch.await();
		}
		catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Remove a listener for OSGi framework events.
	 * 
	 * @param bundleHostListener the listener
	 */
	public void removeListener(BundleHostListener bundleHostListener) {
		listeners.remove(bundleHostListener);
	}

	protected void activateAll(Collection<GhidraBundle> bundles, TaskMonitor monitor,
			PrintWriter console) {
		List<GhidraBundle> bundlesRemaining = new ArrayList<>(bundles);

		monitor.setMaximum(bundlesRemaining.size());
		while (!bundlesRemaining.isEmpty() && !monitor.isCancelled()) {
			List<GhidraBundle> resolvableBundles = bundlesRemaining.stream()
					.filter(bundle -> canResolveAll(bundle.getAllRequirements()))
					.collect(Collectors.toList());
			if (resolvableBundles.isEmpty()) {
				// final round, try everything we couldn't resolve to generate errors
				resolvableBundles = bundlesRemaining;
				bundlesRemaining = Collections.emptyList();
			}
			else {
				bundlesRemaining.removeAll(resolvableBundles);
			}

			for (GhidraBundle bundle : resolvableBundles) {
				if (monitor.isCancelled()) {
					break;
				}
				try {
					bundle.build(console);
					activateSynchronously(bundle.getLocationIdentifier());
				}
				catch (Exception e) {
					e.printStackTrace(console);
				}
				monitor.incrementProgress(1);
			}
		}
	}

	/**
	 * Used by {@link GhidraBundle}s to notify the host that a bundle has been built.
	 * 
	 * @param bundle the bundle that was built
	 * @param summary a summary of anything notable (errors or warnings) during the build
	 */
	void notifyBundleBuilt(GhidraBundle bundle, String summary) {
		fireBundleBuilt(bundle, summary);
	}

	private void fireBundleBuilt(GhidraBundle bundle, String summary) {
		for (BundleHostListener l : listeners) {
			l.bundleBuilt(bundle, summary);
		}
	}

	private void fireBundleEnablementChange(GhidraBundle bundle, boolean newEnablement) {
		for (BundleHostListener l : listeners) {
			l.bundleEnablementChange(bundle, newEnablement);
		}
	}

	private void fireBundleActivationChange(GhidraBundle bundle, boolean newEnablement) {
		for (BundleHostListener l : listeners) {
			l.bundleActivationChange(bundle, newEnablement);
		}
	}

	private void fireBundleAdded(GhidraBundle bundle) {
		for (BundleHostListener l : listeners) {
			l.bundleAdded(bundle);
		}
	}

	private void fireBundleRemoved(GhidraBundle bundle) {
		for (BundleHostListener l : listeners) {
			l.bundleRemoved(bundle);
		}
	}

	private void fireBundlesAdded(Collection<GhidraBundle> gbundles) {
		for (BundleHostListener l : listeners) {
			l.bundlesAdded(gbundles);
		}
	}

	private void fireBundlesRemoved(Collection<GhidraBundle> gbundles) {
		for (BundleHostListener l : listeners) {
			l.bundlesRemoved(gbundles);
		}
	}

	private void fireBundleException(GhidraBundleException exception) {
		for (BundleHostListener l : listeners) {
			l.bundleException(exception);
		}
	}

	/**
	 * Add a listener for OSGi framework events.
	 * 
	 * @param bundleHostListener the listener
	 */
	public void addListener(BundleHostListener bundleHostListener) {
		listeners.add(bundleHostListener);
	}

	private void startActivateAllTask(Collection<GhidraBundle> bundlesToActivate) {
		if (!bundlesToActivate.isEmpty()) {
			new TaskLauncher(new Task("restoring bundle state", true, true, false) {
				@Override
				public void run(TaskMonitor monitor) throws CancelledException {
					activateAll(bundlesToActivate, monitor, new NullPrintWriter());
				}
			});
		}
	}

	/**
	 * Restore the list of managed bundles from {@code saveState} and each bundle's state.
	 * 
	 * <p>Bundles that had been active are reactivated.
	 * 
	 * <p>note: This is done once on startup after system bundles have been added.
	 * 
	 * @param saveState the state object
	 * @param tool the tool
	 */
	public void restoreManagedBundleState(SaveState saveState, PluginTool tool) {
		String[] bundleFiles = saveState.getStrings(SAVE_STATE_TAG_FILE, new String[0]);

		boolean[] bundleIsEnabled =
			saveState.getBooleans(SAVE_STATE_TAG_ENABLE, new boolean[bundleFiles.length]);
		boolean[] bundleIsActive =
			saveState.getBooleans(SAVE_STATE_TAG_ACTIVE, new boolean[bundleFiles.length]);
		boolean[] bundleIsSystem =
			saveState.getBooleans(SAVE_STATE_TAG_SYSTEM, new boolean[bundleFiles.length]);

		List<GhidraBundle> newBundles = new ArrayList<>();
		List<GhidraBundle> bundlesToActivate = new ArrayList<>();
		for (int i = 0; i < bundleFiles.length; i++) {
			ResourceFile bundleFile = generic.util.Path.fromPathString(bundleFiles[i]);
			boolean isEnabled = bundleIsEnabled[i];
			boolean isActive = bundleIsActive[i];
			boolean isSystem = bundleIsSystem[i];
			GhidraBundle bundle = fileToBundleMap.get(bundleFile);
			if (bundle != null) {
				if (isEnabled != bundle.isEnabled()) {
					bundle.setEnabled(isEnabled);
					fireBundleEnablementChange(bundle, isEnabled);
				}
				if (isSystem != bundle.isSystemBundle()) {
					bundle.systemBundle = isSystem;
					Msg.error(this, String.format("Error, bundle %s went from %system to %system", bundleFile,
						isSystem ? "not " : "", isSystem ? "" : "not "));
				}
			}
			else if (isSystem) {
				// stored system bundles that weren't already initialized must be old, drop 'm.
			}
			else {
				bundle = createGhidraBundle(this, bundleFile, isEnabled, isSystem);
				newBundles.add(bundle);
			}
			if (bundle != null && isActive) {
				bundlesToActivate.add(bundle);
			}
		}
		add(newBundles);
		startActivateAllTask(bundlesToActivate);
	}

	/**
	 * Save the list of managed bundles and each bundle's state.
	 * 
	 * @param saveState the state object
	 */
	public void saveManagedBundleState(SaveState saveState) {
		int numBundles = fileToBundleMap.size();
		String[] bundleFiles = new String[numBundles];
		boolean[] bundleIsEnabled = new boolean[numBundles];
		boolean[] bundleIsActive = new boolean[numBundles];
		boolean[] bundleIsSystem = new boolean[numBundles];

		int index = 0;
		for (GhidraBundle bundle : fileToBundleMap.values()) {
			bundleFiles[index] = generic.util.Path.toPathString(bundle.getFile());
			bundleIsEnabled[index] = bundle.isEnabled();
			bundleIsActive[index] = bundle.isActive();
			bundleIsSystem[index] = bundle.isSystemBundle();
			++index;
		}

		saveState.putStrings(SAVE_STATE_TAG_FILE, bundleFiles);
		saveState.putBooleans(SAVE_STATE_TAG_ENABLE, bundleIsEnabled);
		saveState.putBooleans(SAVE_STATE_TAG_ACTIVE, bundleIsActive);
		saveState.putBooleans(SAVE_STATE_TAG_SYSTEM, bundleIsSystem);
	}

	/**
	 * The {@code BundleListener} that notifies {@link BundleHostListener}s of bundle activation changes
	 */
	private class MyBundleListener implements BundleListener {
		private final Bundle systemBundle;

		private MyBundleListener(Bundle systemBundle) {
			this.systemBundle = systemBundle;
		}

		@Override
		public void bundleChanged(BundleEvent event) {
			Bundle osgiBundle = event.getBundle();

			// ignore events on the system bundle
			if (osgiBundle == systemBundle) {
				return;
			}
			if (STDERR_DEBUGGING) {
				String symbolicName = osgiBundle.getSymbolicName();
				String locationIdentifier = osgiBundle.getLocation();
				System.err.printf("%s %s from %s\n", OSGiUtils.getEventTypeString(event),
					symbolicName, locationIdentifier);
			}
			GhidraBundle bundle;
			switch (event.getType()) {
				case BundleEvent.STARTED:
					bundle = bundleLocationToBundleMap.get(osgiBundle.getLocation());
					if (bundle != null) {
						fireBundleActivationChange(bundle, true);
					}
					else {
						Msg.error(this,
							String.format("Error, bundle event for non-GhidraBundle: %s\n", osgiBundle.getLocation()));
					}
					break;
				// force "inactive" updates for all other states
				default:
					bundle = bundleLocationToBundleMap.get(osgiBundle.getLocation());
					if (bundle != null) {
						fireBundleActivationChange(bundle, false);
					}
					else {
						Msg.error(this,
							String.format("Error, bundle event for non-GhidraBundle: %s\n", osgiBundle.getLocation()));
					}
					break;
			}
		}
	}
}
