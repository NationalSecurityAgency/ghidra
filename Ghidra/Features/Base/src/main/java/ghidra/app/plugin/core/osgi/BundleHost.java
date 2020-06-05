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
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.felix.framework.FrameworkFactory;
import org.apache.felix.framework.Logger;
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
 * - unqualified, "bundle" will mean {@link GhidraBundle}
 * - use of OSGi types, including {@link Bundle} and {@link Framework}, should be package scoped (not public)  
 * - OSGi bundle lifecycle is simplified to "active" and "inactive" (OSGi's "uninstalled" state)
 */
public class BundleHost {
	protected static final boolean STDERR_DEBUGGING = false;
	private static final String saveStateTagPath = "BundleHost_PATH";
	private static final String saveStateTagEnabled = "BundleHost_ENABLE";
	private static final String saveStateTagActive = "BundleHost_ACTIVE";
	private static final String saveStateTagSystem = "BundleHost_SYSTEM";

	HashMap<ResourceFile, GhidraBundle> bundlePathToBundleMap = new HashMap<>();
	HashMap<String, GhidraBundle> bundleLocationToBundleMap = new HashMap<>();

	BundleContext frameworkBundleContext;
	Framework felixFramework;

	List<BundleHostListener> listeners = new ArrayList<>();

	/** constructor */
	public BundleHost() {
		//
	}

	private static GhidraBundle newGhidraBundle(BundleHost bundleHost, ResourceFile bundlePath,
			boolean enabled, boolean systemBundle) {
		switch (GhidraBundle.getType(bundlePath)) {
			case SourceDir:
				return new GhidraSourceBundle(bundleHost, bundlePath, enabled, systemBundle);
			case Jar:
				return new GhidraJarBundle(bundleHost, bundlePath, enabled, systemBundle);
			case BndScript:
			default:
				break;
		}
		return new GhidraPlaceholderBundle(bundleHost, bundlePath, enabled, systemBundle);
	}

	/**
	 * stop the framework.
	 */
	public void dispose() {
		stopFramework();
	}

	/**
	 * If there is currently a bundle managed with path {@code bundlePath}, return its {@link GhidraBundle}, 
	 * otherwise return {@code null}. 
	 * 
	 * @param bundlePath the bundlePath of the sought bundle
	 * @return a {@link GhidraBundle} or {@code null}
	 */
	public GhidraBundle getExistingGhidraBundle(ResourceFile bundlePath) {
		GhidraBundle bundle = bundlePathToBundleMap.get(bundlePath);
		if (bundle == null) {
			Msg.showError(this, null, "ghidra bundle cache",
				"getExistingGhidraBundle expected a GhidraBundle created at " + bundlePath +
					" but none was found");
		}
		return bundle;
	}

	/**
	 * If a {@link GhidraBundle} hasn't already been added for {@bundlePath}, add it now as a 
	 * non-system bundle.
	 * 
	 * Enable the bundle.
	 * 
	 * @param bundlePath the path to the bundle to (add and) enable
	 * @return false if the bundle was already enabled
	 */
	public boolean enablePath(ResourceFile bundlePath) {
		GhidraBundle bundle = bundlePathToBundleMap.get(bundlePath);
		if (bundle == null) {
			bundle = add(bundlePath, true, false);
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
	 * Create a new GhidraBundle and add to the list of managed bundles
	 * 
	 * @param bundlePath the bundle's path
	 * @param enabled if the new bundle should be enabled
	 * @param systemBundle if the new bundle is a system bundle
	 * @return a new GhidraBundle
	 */
	public GhidraBundle add(ResourceFile bundlePath, boolean enabled, boolean systemBundle) {
		GhidraBundle bundle = newGhidraBundle(this, bundlePath, enabled, systemBundle);
		bundlePathToBundleMap.put(bundlePath, bundle);
		bundleLocationToBundleMap.put(bundle.getBundleLocation(), bundle);
		fireBundleAdded(bundle);
		return bundle;
	}

	/**
	 * Create new GhidraBundles and add to the list of managed bundles.  All GhidraBundles created 
	 * with the same {@code enabled} and {@code systemBundle} values. 
	 * 
	 * @param bundlePaths a list of bundle paths
	 * @param enabled if the new bundle should be enabled
	 * @param systemBundle if the new bundle is a system bundle
	 */
	public void add(List<ResourceFile> bundlePaths, boolean enabled, boolean systemBundle) {
		Map<ResourceFile, GhidraBundle> newBundleMap = bundlePaths.stream()
			.collect(Collectors.toUnmodifiableMap(Function.identity(),
				bundlePath -> newGhidraBundle(BundleHost.this, bundlePath, enabled, systemBundle)));
		bundlePathToBundleMap.putAll(newBundleMap);
		bundleLocationToBundleMap.putAll(newBundleMap.values()
			.stream()
			.collect(
				Collectors.toUnmodifiableMap(GhidraBundle::getBundleLocation, Function.identity())));
		fireBundlesAdded(newBundleMap.values());
	}

	/**
	 * Add bundles to the list of managed bundles.
	 * 
	 * @param bundles the bundles to add
	 */
	public void add(List<GhidraBundle> bundles) {
		for (GhidraBundle bundle : bundles) {
			bundlePathToBundleMap.put(bundle.getPath(), bundle);
			bundleLocationToBundleMap.put(bundle.getBundleLocation(), bundle);
		}
		fireBundlesAdded(bundles);
	}

	/**
	 * Remove a bundle from the list of managed bundles.
	 * 
	 * @param bundlePath the path of the bundle to remove
	 */
	public void removeBundlePath(ResourceFile bundlePath) {
		GhidraBundle bundle = bundlePathToBundleMap.remove(bundlePath);
		bundleLocationToBundleMap.remove(bundle.getBundleLocation());
		fireBundleRemoved(bundle);
	}

	/**
	 * Remove a bundle from the list of managed bundles.
	 * 
	 * @param bundleLocation the location id of the bundle to remove
	 */
	public void removeBundleLoc(String bundleLocation) {
		GhidraBundle bundle = bundleLocationToBundleMap.remove(bundleLocation);
		bundlePathToBundleMap.remove(bundle.getPath());
		fireBundleRemoved(bundle);
	}

	/**
	 * Remove a bundle from the list of managed bundles.
	 * 
	 * @param bundle the bundle to remove
	 */
	public void remove(GhidraBundle bundle) {
		bundlePathToBundleMap.remove(bundle.getPath());
		bundleLocationToBundleMap.remove(bundle.getBundleLocation());
		fireBundleRemoved(bundle);
	}

	/**
	 * Remove bundles from the list of managed bundles.
	 * 
	 * @param bundles the bundles to remove
	 */
	public void remove(Collection<GhidraBundle> bundles) {
		for (GhidraBundle bundle : bundles) {
			bundlePathToBundleMap.remove(bundle.getPath());
			bundleLocationToBundleMap.remove(bundle.getBundleLocation());
		}
		fireBundlesRemoved(bundles);
	}

	Bundle installFromPath(Path p) throws GhidraBundleException {
		return installFromLoc("file://" + p.toAbsolutePath().normalize().toString());
	}

	/**
	 * Try to install a bundle.
	 * 
	 * 
	 * @param bundle the bundle to install
	 * @return the OSGi bundle returned by the framework
	 * @throws GhidraBundleException when install fails
	 */
	public Bundle install(GhidraBundle bundle) throws GhidraBundleException {
		try {
			return frameworkBundleContext.installBundle(bundle.getBundleLocation());
		}
		catch (BundleException e) {
			throw new GhidraBundleException(bundle.getBundleLocation(),
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
		return bundlePathToBundleMap.values();
	}

	/**
	 * return paths of currently managed bundles
	 * 
	 * @return all the bundle paths
	 */
	public Collection<ResourceFile> getBundlePaths() {
		return bundlePathToBundleMap.keySet();
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
	 * @param reqs list of requirements -- satisfied requirements are removed as capabiliites are found
	 * @return the list of BundeWiring objects correpsonding to matching capabilities
	 */
	public List<BundleWiring> resolve(List<BundleRequirement> reqs) {
		// enumerate active bundles, looking for capabilities meeting our requirements
		List<BundleWiring> bundleWirings = new ArrayList<>();
		for (Bundle bundle : frameworkBundleContext.getBundles()) {
			if (bundle.getState() == Bundle.ACTIVE) {
				BundleWiring bw = bundle.adapt(BundleWiring.class);
				boolean keeper = false;
				for (BundleCapability cap : bw.getCapabilities(null)) {
					Iterator<BundleRequirement> it = reqs.iterator();
					while (it.hasNext()) {
						BundleRequirement req = it.next();
						if (req.matches(cap)) {
							it.remove();
							keeper = true;
						}
					}
				}
				if (keeper) {
					bundleWirings.add(bw);
				}
			}
		}
		return bundleWirings;
	}

	/**
	 * Attempt to resolve {@code requirements} against the currently active bundles.
	 * 
	 * @param requirements a list of {@link BundleRequirement} objects
	 * @return true if all of the requiremetns can be resolved
	 */
	public boolean canResolveAll(Collection<BundleRequirement> requirements) {
		LinkedList<BundleRequirement> tmpRequirements = new LinkedList<>(requirements);
		resolve(tmpRequirements);
		return tmpRequirements.isEmpty();
	}

	private class FelixStderrLogger extends Logger {
		@Override
		protected void doLog(int level, String message, Throwable throwable) {
			System.err.printf("felixlogger: %s %s\n", message, throwable);
		}

		@Override
		protected void doLogOut(int level, String message, Throwable throwable) {
			System.err.printf("felixlogger: %s %s\n", message, throwable);
		}

		@SuppressWarnings("rawtypes")

		@Override
		protected void doLog(final Bundle bundle, final ServiceReference sr, final int level,
				final String message, final Throwable throwable) {
			System.err.printf("felixlogger: %s %s %s\n", bundle, message, throwable);
		}

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
	 * A directory for use by Felix as a cache
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
			config.put(FelixConstants.LOG_LOGGER_PROP, new FelixStderrLogger());
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
	 * add the {@code BundleListener} that notifies listeners of bundle activation changes
	 */
	protected void addBundleListener() {
		final Bundle systemBundle = frameworkBundleContext.getBundle();
		frameworkBundleContext.addBundleListener(new BundleListener() {
			@Override
			public void bundleChanged(BundleEvent event) {
				Bundle osgiBundle = event.getBundle();

				// ignore events on the system bundle
				if (osgiBundle == systemBundle) {
					return;
				}
				if (STDERR_DEBUGGING) {
					String n = osgiBundle.getSymbolicName();
					String l = osgiBundle.getLocation();
					System.err.printf("%s %s from %s\n", OSGiUtils.getEventTypeString(event), n, l);
				}
				GhidraBundle bundle;
				switch (event.getType()) {
					case BundleEvent.STARTED:
						bundle = bundleLocationToBundleMap.get(osgiBundle.getLocation());
						if (bundle != null) {
							fireBundleActivationChange(bundle, true);
						}
						else {
							Msg.error(this, String.format("not a GhidraBundle: %s\n",
								osgiBundle.getLocation()));
						}
						break;
					case BundleEvent.UNINSTALLED:
						bundle = bundleLocationToBundleMap.get(osgiBundle.getLocation());
						if (bundle != null) {
							fireBundleActivationChange(bundle, false);
						}
						else {
							Msg.error(this, String.format("not a GhidraBundle: %s\n",
								osgiBundle.getLocation()));
						}
						break;
					default:
						break;
				}
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

		addBundleListener();

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
				felixFramework.waitForStop(5000);
				felixFramework = null;
			}
			catch (BundleException | InterruptedException e) {
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

	private static boolean anyMatch(Bundle bundle, int... bundleStates) {
		Integer s = bundle.getState();
		return IntStream.of(bundleStates).anyMatch(s::equals);
	}

	private static void waitFor(Bundle bundle, int... bundleStates) throws InterruptedException {
		while (true) {
			if (anyMatch(bundle, bundleStates)) {
				return;
			}
			Thread.sleep(500);
		}
	}

	/**
	 * Activate a bundle, returning only after the bundle is active.
	 * 
	 * @param bundle the bundle
	 * @throws InterruptedException if the wait is interrupted
	 * @throws GhidraBundleException if there's a problem activating
	 */
	public void activateSynchronously(Bundle bundle)
			throws InterruptedException, GhidraBundleException {
		if (bundle.getState() == Bundle.ACTIVE) {
			return;
		}
		try {
			bundle.start();
		}
		catch (BundleException e) {
			GhidraBundleException gbe = new GhidraBundleException(bundle, "activating bundle", e);
			fireBundleException(gbe);
			throw gbe;
		}
		waitFor(bundle, Bundle.ACTIVE);
	}

	/**
	 * Activate a bundle, returning only after the bundle is active.
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
	 * Deactivate a bundle, returning only after the bundle is inactive.
	 * 
	 * @param bundle the bundle
	 * @throws InterruptedException if the wait is interrupted
	 * @throws GhidraBundleException if there's a problem activating
	 */
	public void deactivateSynchronously(Bundle bundle)
			throws InterruptedException, GhidraBundleException {
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
				frameworkWiring.refreshBundles(dependentBundles);
			}
			catch (BundleException e) {
				GhidraBundleException exception =
					new GhidraBundleException(dependentBundle, "deactivating bundle", e);
				fireBundleException(exception);
				throw exception;
			}
			waitFor(dependentBundle, Bundle.UNINSTALLED);
		}
	}

	/**
	 * Deactivate a bundle, returning only after the bundle is inactive.
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
	 * Remove a listener for OSGi framework events.
	 * 
	 * @param bundleHostListener the listener
	 */
	public void removeListener(BundleHostListener bundleHostListener) {
		synchronized (listeners) {
			listeners.remove(bundleHostListener);
		}
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
					activateSynchronously(bundle.getBundleLocation());
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
		synchronized (listeners) {
			for (BundleHostListener l : listeners) {
				l.bundleBuilt(bundle, summary);
			}
		}
	}

	private void fireBundleEnablementChange(GhidraBundle bundle, boolean newEnablement) {
		synchronized (listeners) {
			for (BundleHostListener l : listeners) {
				l.bundleEnablementChange(bundle, newEnablement);
			}
		}
	}

	private void fireBundleActivationChange(GhidraBundle bundle, boolean newEnablement) {
		synchronized (listeners) {
			for (BundleHostListener l : listeners) {
				l.bundleActivationChange(bundle, newEnablement);
			}
		}
	}

	private void fireBundleAdded(GhidraBundle bundle) {
		synchronized (listeners) {
			for (BundleHostListener l : listeners) {
				l.bundleAdded(bundle);
			}
		}
	}

	private void fireBundleRemoved(GhidraBundle bundle) {
		synchronized (listeners) {
			for (BundleHostListener l : listeners) {
				l.bundleRemoved(bundle);
			}
		}
	}

	private void fireBundlesAdded(Collection<GhidraBundle> gbundles) {
		synchronized (listeners) {
			for (BundleHostListener l : listeners) {
				l.bundlesAdded(gbundles);
			}
		}
	}

	private void fireBundlesRemoved(Collection<GhidraBundle> gbundles) {
		synchronized (listeners) {
			for (BundleHostListener l : listeners) {
				l.bundlesRemoved(gbundles);
			}
		}
	}

	private void fireBundleException(GhidraBundleException gbe) {
		synchronized (listeners) {
			for (BundleHostListener l : listeners) {
				l.bundleException(gbe);
			}
		}
	}

	/**
	 * Add a listener for OSGi framework events.
	 * 
	 * @param bundleHostListener the listener
	 */
	public void addListener(BundleHostListener bundleHostListener) {
		synchronized (listeners) {
			listeners.add(bundleHostListener);
		}
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
	 * Bundles that had been active are reactivated.
	 * 
	 * note: This is done once on startup, AFTER system bundles have been added.
	 * 
	 * @param saveState the state object
	 * @param tool the tool
	 */
	public void restoreManagedBundleState(SaveState saveState, PluginTool tool) {
		String[] bundlePaths = saveState.getStrings(saveStateTagPath, new String[0]);

		boolean[] bundleIsEnabled =
			saveState.getBooleans(saveStateTagEnabled, new boolean[bundlePaths.length]);
		boolean[] bundleIsActive =
			saveState.getBooleans(saveStateTagActive, new boolean[bundlePaths.length]);
		boolean[] bundleIsSystem =
			saveState.getBooleans(saveStateTagSystem, new boolean[bundlePaths.length]);

		List<GhidraBundle> newBundles = new ArrayList<>();
		List<GhidraBundle> bundlesToActivate = new ArrayList<>();
		for (int i = 0; i < bundlePaths.length; i++) {
			ResourceFile bundlePath = generic.util.Path.fromPathString(bundlePaths[i]);
			boolean isEnabled = bundleIsEnabled[i];
			boolean isActive = bundleIsActive[i];
			boolean isSystem = bundleIsSystem[i];
			GhidraBundle bundle = bundlePathToBundleMap.get(bundlePath);
			if (bundle != null) {
				if (isEnabled != bundle.isEnabled()) {
					bundle.setEnabled(isEnabled);
					fireBundleEnablementChange(bundle, isEnabled);
				}
				if (isSystem != bundle.isSystemBundle()) {
					bundle.systemBundle = isSystem;
					Msg.error(this, String.format("%s went from %system to %system", bundlePath,
						isSystem ? "not " : "", isSystem ? "" : "not "));
				}
			}
			else if (isSystem) {
				// stored system bundles that weren't already initialized must be old, drop 'm.
			}
			else {
				newBundles.add(bundle = newGhidraBundle(this, bundlePath, isEnabled, isSystem));
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
		int numBundles = bundlePathToBundleMap.size();
		String[] bundlePaths = new String[numBundles];
		boolean[] bundleIsEnabled = new boolean[numBundles];
		boolean[] bundleIsActive = new boolean[numBundles];
		boolean[] bundleIsSystem = new boolean[numBundles];

		int index = 0;
		for (GhidraBundle bundle : bundlePathToBundleMap.values()) {
			bundlePaths[index] = generic.util.Path.toPathString(bundle.getPath());
			bundleIsEnabled[index] = bundle.isEnabled();
			bundleIsActive[index] = bundle.isActive();
			bundleIsSystem[index] = bundle.isSystemBundle();
			++index;
		}

		saveState.putStrings(saveStateTagPath, bundlePaths);
		saveState.putBooleans(saveStateTagEnabled, bundleIsEnabled);
		saveState.putBooleans(saveStateTagActive, bundleIsActive);
		saveState.putBooleans(saveStateTagSystem, bundleIsSystem);
	}

}
