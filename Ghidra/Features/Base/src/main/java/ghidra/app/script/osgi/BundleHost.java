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
package ghidra.app.script.osgi;

import static java.util.stream.Collectors.*;

import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.*;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.*;

import org.apache.felix.framework.FrameworkFactory;
import org.apache.felix.framework.util.FelixConstants;
import org.apache.felix.framework.util.manifestparser.ManifestParser;
import org.apache.felix.main.AutoProcessor;
import org.osgi.framework.*;
import org.osgi.framework.launch.Framework;
import org.osgi.framework.wiring.*;
import org.osgi.service.log.*;

import generic.io.NullPrintWriter;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

// XXX this class should be part of a service/plugin
public class BundleHost {
	// XXX embedded OSGi should be a service, but ScriptProviders don't have any way to access services
	static private BundleHost _instance;

	static public BundleHost getInstance() {
		if (_instance == null) {
			_instance = new BundleHost();
			try {
				_instance.startFelix();
			}
			catch (OSGiException | IOException e) {
				throw new RuntimeException(e);
			}
		}
		return _instance;
	}

	static public String getSymbolicNameFromSourceDir(ResourceFile sourceDir) {
		return Integer.toHexString(sourceDir.getAbsolutePath().hashCode());
	}

	public void dispose() {
		if (felix != null) {
			forceStopFelix();
		}
	}

	// XXX this should be remembered in bundlehosts's savestate
	HashMap<ResourceFile, SourceBundleInfo> file2sbi = new HashMap<>();

	public SourceBundleInfo getSourceBundleInfo(ResourceFile sourceDir) {
		return file2sbi.computeIfAbsent(sourceDir, sd -> new SourceBundleInfo(this, sd));
	}

	// XXX consumers must clean up after themselves
	public void removeSourceBundleInfo(ResourceFile sourceDir) {
		file2sbi.remove(sourceDir);
	}

	/**
	 * parse Import-Package string from a bundle manifest
	 * 
	 * @param imports Import-Package value
	 * @return deduced requirements or null if there was an error
	 * @throws OSGiException on parse failure 
	 */
	static List<BundleRequirement> parseImports(String imports) throws OSGiException {

		// parse it with Felix's ManifestParser to a list of BundleRequirement objects
		Map<String, Object> headerMap = new HashMap<>();
		headerMap.put(Constants.IMPORT_PACKAGE, imports);
		ManifestParser mp;
		try {
			mp = new ManifestParser(null, null, null, headerMap);
			return mp.getRequirements();
		}
		catch (org.osgi.framework.BundleException e) {
			throw new OSGiException("parsing Import-Package: " + imports, e);
		}
	}

	/**
	 * cache of data corresponding to a source directory that is bound to be an exploded bundle
	 */
	protected static class BuildFailure {
		long when = -1;
		StringBuilder message = new StringBuilder();
	}

	String buildExtraPackages() {
		Set<String> packages = new HashSet<>();
		getPackagesFromClasspath(packages);
		return packages.stream().collect(Collectors.joining(","));
	}

	BundleContext bc;
	Framework felix;
	Bundle fileinstall_bundle;

	Bundle installFromPath(Path p) throws GhidraBundleException {
		return installFromLoc("file://" + p.toAbsolutePath().normalize().toString());
	}

	public Bundle installFromLoc(String bundle_loc) throws GhidraBundleException {
		try {
			return bc.installBundle(bundle_loc);
		}
		catch (BundleException e) {
			throw new GhidraBundleException(bundle_loc, "installing from bundle location", e);
		}
	}

	Bundle installAsLoc(String bundle_loc, InputStream contents) throws GhidraBundleException {
		try {
			return bc.installBundle(bundle_loc, contents);
		}
		catch (BundleException e) {
			throw new GhidraBundleException(bundle_loc, "installing as bundle location", e);
		}
	}

	void dumpLoadedBundles() {
		System.err.printf("=== Bundles ===\n");
		for (Bundle bundle : bc.getBundles()) {
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
		for (Bundle b : bc.getBundles()) {
			if (b.getState() == Bundle.ACTIVE) {
				BundleWiring bw = b.adapt(BundleWiring.class);
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

	public boolean canResolveAll(Collection<BundleRequirement> reqs) {
		LinkedList<BundleRequirement> tmp = new LinkedList<>(reqs);
		resolve(tmp);
		return tmp.isEmpty();
	}

	class FelixLogger extends org.apache.felix.framework.Logger {
		@Override
		protected void doLog(int level, String msg, Throwable throwable) {
			// plugin.printf("felixlogger: %s %s\n", msg, throwable);
		}

		@Override
		protected void doLogOut(int level, String s, Throwable throwable) {
			// plugin.printf("felixlogger: %s %s\n", s, throwable);
		}

		@SuppressWarnings("rawtypes")

		@Override
		protected void doLog(final Bundle bundle, final ServiceReference sr, final int level,
				final String msg, final Throwable throwable) {
			// plugin.printf("felixlogger: %s %s %s\n", bundle, msg, throwable);
		}

	}

	static String getEventTypeString(BundleEvent e) {
		switch (e.getType()) {
			case BundleEvent.INSTALLED:
				return "INSTALLED";
			case BundleEvent.RESOLVED:
				return "RESOLVED";
			case BundleEvent.LAZY_ACTIVATION:
				return "LAZY_ACTIVATION";
			case BundleEvent.STARTING:
				return "STARTING";
			case BundleEvent.STARTED:
				return "STARTED";
			case BundleEvent.STOPPING:
				return "STOPPING";
			case BundleEvent.STOPPED:
				return "STOPPED";
			case BundleEvent.UPDATED:
				return "UPDATED";
			case BundleEvent.UNRESOLVED:
				return "UNRESOLVED";
			case BundleEvent.UNINSTALLED:
				return "UNINSTALLED";
			default:
				return "???";
		}
	}

	/**
	 * start the framework
	 * 
	 * @throws OSGiException framework failures
	 * @throws IOException filesystem setup
	 */
	public void startFelix() throws OSGiException, IOException {

		Properties config = new Properties();

		config.setProperty(Constants.FRAMEWORK_BSNVERSION, Constants.FRAMEWORK_BSNVERSION_MULTIPLE);
		config.setProperty(Constants.FRAMEWORK_SYSTEMCAPABILITIES,
			"osgi.ee; osgi.ee=\"JavaSE\";version:List=\"11\"");
		config.setProperty(Constants.FRAMEWORK_SYSTEMPACKAGES_EXTRA, buildExtraPackages());
		// extra packages have lower precedence than imports, so a Bundle-Import will
		// prevent "living off the land"

		config.setProperty("org.osgi.service.http.port", "8080");

		config.setProperty(Constants.FRAMEWORK_STORAGE_CLEAN,
			Constants.FRAMEWORK_STORAGE_CLEAN_ONFIRSTINIT);
		config.setProperty(Constants.FRAMEWORK_STORAGE, makeCacheDir());

		// more properties available at:
		// http://felix.apache.org/documentation/subprojects/apache-felix-service-component-runtime.html
		config.setProperty("ds.showtrace", "true");
		config.setProperty("ds.showerrors", "true");

		config.put(FelixConstants.LOG_LEVEL_PROP, "999");// was 4
		config.put(FelixConstants.LOG_LOGGER_PROP, new FelixLogger());

		FrameworkFactory factory = new FrameworkFactory();
		felix = factory.newFramework(config);

		try {
			felix.init();
		}
		catch (BundleException e) {
			throw new OSGiException("initializing felix OSGi framework", e);
		}
		bc = felix.getBundleContext();
		AutoProcessor.process(config, bc);

		ServiceReference<LogReaderService> ref = bc.getServiceReference(LogReaderService.class);
		if (ref != null) {
			LogReaderService reader = bc.getService(ref);
			reader.addLogListener(new LogListener() {

				@Override
				public void logged(LogEntry entry) {
					// plugin.printf("%s: %s\n", entry.getBundle(), entry.getMessage());
				}
			});
		}
		else {
			// plugin.printf("no logreaderservice in felix!\n");
		}

		bc.addFrameworkListener(new FrameworkListener() {

			@Override
			public void frameworkEvent(FrameworkEvent event) {
				System.err.printf("%s %s\n", event.getBundle(), event);
			}
		});

		bc.addServiceListener(new ServiceListener() {
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
		bc.addBundleListener(new BundleListener() {
			@Override
			public void bundleChanged(BundleEvent event) {
				Bundle b = event.getBundle();
				String n = b.getSymbolicName();
				String l = b.getLocation();
				System.err.printf("%s %s from %s\n", getEventTypeString(event), n, l);
				switch (event.getType()) {
					case BundleEvent.STARTED:
						fireBundleActivationChange(b, true);
						break;
					case BundleEvent.UNINSTALLED:
						fireBundleActivationChange(b, false);
						break;
					default:
						break;
				}
			}
		});

		try {
			felix.start();
		}
		catch (BundleException e) {
			throw new OSGiException("starting felix OSGi framework", e);
		}
	}

	private String makeCacheDir() throws IOException {
		Path cache_dir = GhidraScriptUtil.getOsgiDir().resolve("felixcache");
		Files.createDirectories(cache_dir);
		return cache_dir.toAbsolutePath().toString();
	}

	public Bundle getBundle(String bundleLoc) {
		return bc.getBundle(bundleLoc);
	}

	static private boolean oneOf(Bundle b, int... bundle_states) {
		Integer s = b.getState();
		return IntStream.of(bundle_states).anyMatch(s::equals);
	}

	static private void waitFor(Bundle b, int... bundle_states) throws InterruptedException {
		while (true) {
			if (oneOf(b, bundle_states)) {
				return;
			}
			Thread.sleep(500);
		}
	}

	public void activateSynchronously(Bundle b) throws InterruptedException, GhidraBundleException {
		if (b.getState() == Bundle.ACTIVE) {
			return;
		}
		try {
			b.start();
		}
		catch (BundleException e) {
			throw new GhidraBundleException(b, "starting bundle", e);
		}
		waitFor(b, Bundle.ACTIVE);
	}

	public void activateSynchronously(String bundleLoc)
			throws GhidraBundleException, InterruptedException {
		Bundle bundle = getBundle(bundleLoc);
		if (bundle == null) {
			bundle = installFromLoc(bundleLoc);
		}
		activateSynchronously(bundle);
	}

	public void deactivateSynchronously(Bundle b)
			throws InterruptedException, GhidraBundleException {
		if (b.getState() == Bundle.UNINSTALLED) {
			return;
		}
		FrameworkWiring fw = felix.adapt(FrameworkWiring.class);
		LinkedList<Bundle> dependents =
			new LinkedList<Bundle>(fw.getDependencyClosure(Collections.singleton(b)));
		System.err.printf("%s has %d dependendts\n", b.getSymbolicName(), dependents.size());
		while (!dependents.isEmpty()) {
			b = dependents.pop();
			try {
				b.uninstall();
				fw.refreshBundles(dependents);
			}
			catch (BundleException e) {
				throw new GhidraBundleException(b, "uninstalling bundle", e);
			}
			waitFor(b, Bundle.UNINSTALLED);
		}
	}

	void forceStopFelix() {
		Task t = new Task("killing felix", false, false, true, true) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				try {
					felix.stop();
					System.err.printf("trying to kill felix...\n");
					FrameworkEvent x = felix.waitForStop(5000);
					System.err.printf("killed felix with %s", x.toString());
					felix = null;
				}
				catch (BundleException | InterruptedException e) {
					System.err.printf("failed to kill felix: %s", e);
				}
			}

		};
		new TaskLauncher(t, null);
	}

	public Framework getHostFramework() {
		return felix;
	}

	public interface DiscrepencyCallback {
		void found(ResourceFile source_file, Collection<Path> class_files) throws Throwable;
	}

	public static void visitDiscrepencies(ResourceFile srcdir, Path bindir,
			DiscrepencyCallback new_source_cb) {
		try {
			// delete class files for which java is either newer, or no longer exists
			Deque<ResourceFile> stack = new ArrayDeque<>();
			stack.add(srcdir);
			while (!stack.isEmpty()) {
				ResourceFile sd = stack.pop();
				String relpath = sd.getAbsolutePath().substring(srcdir.getAbsolutePath().length());
				if (relpath.startsWith(File.separator)) {
					relpath = relpath.substring(1);
				}
				Path bd = bindir.resolve(relpath);

				// index the class files in the corresponding directory by basename
				Map<String, List<Path>> binfiles =
					Files.exists(bd) ? Files.list(bd).filter(x -> Files.isRegularFile(x) &&
						x.getFileName().toString().endsWith(".class")).collect(groupingBy(x -> {
							String s = x.getFileName().toString();
							int money = s.indexOf('$');
							if (money >= 0) {
								return s.substring(0, money);
							}
							return s.substring(0, s.length() - 6);
						})) : Collections.emptyMap();

				for (ResourceFile sf : sd.listFiles()) {
					if (sf.isDirectory()) {
						stack.push(sf);
					}
					else {
						String n = sf.getName();
						if (n.endsWith(".java")) {
							long sfl = sf.lastModified();
							List<Path> bfs = binfiles.remove(n.substring(0, n.length() - 5));
							long bfl = (bfs == null || bfs.isEmpty()) ? -1
									: bfs.stream().mapToLong(
										bf -> bf.toFile().lastModified()).min().getAsLong();
							if (sfl > bfl) {
								new_source_cb.found(sf, bfs);
							}
						}
					}
				}
				// any remaining .class files are missing .java files
				if (!binfiles.isEmpty()) {
					new_source_cb.found(null,
						binfiles.values().stream().flatMap(l -> l.stream()).collect(
							Collectors.toList()));
				}
			}
		}
		catch (Throwable t) {
			t.printStackTrace();
		}
	}

	// from https://dzone.com/articles/locate-jar-classpath-given
	static String findJarForClass(Class<?> c) {
		final URL location;
		final String classLocation = c.getName().replace('.', '/') + ".class";
		final ClassLoader loader = c.getClassLoader();
		if (loader == null) {
			location = ClassLoader.getSystemResource(classLocation);
		}
		else {
			location = loader.getResource(classLocation);
		}
		if (location != null) {
			Pattern p = Pattern.compile("^.*:(.*)!.*$");
			Matcher m = p.matcher(location.toString());
			if (m.find()) {
				return m.group(1);
			}
			return null; // not loaded from jar?
		}
		return null;
	}

	static void getPackagesFromClasspath(Set<String> s) {
		getClasspathElements().forEach(p -> {
			if (Files.isDirectory(p)) {
				collectPackagesFromDirectory(p, s);
			}
			else if (p.toString().endsWith(".jar")) {
				collectPackagesFromJar(p, s);
			}
		});
	}

	static Stream<Path> getClasspathElements() {
		String classpathStr = System.getProperty("java.class.path");
		return Collections.list(new StringTokenizer(classpathStr, File.pathSeparator)).stream().map(
			String.class::cast).map(Paths::get).map(Path::normalize);
	}

	static void collectPackagesFromDirectory(Path dirPath, Set<String> s) {
		try {
			Files.walk(dirPath).filter(p -> p.toString().endsWith(".class")).forEach(p -> {
				String n = dirPath.relativize(p).toString();
				int lastSlash = n.lastIndexOf('/');
				s.add(lastSlash > 0 ? n.substring(0, lastSlash).replace('/', '.') : "");
			});

		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	static void collectPackagesFromJar(Path jarPath, Set<String> s) {
		try {
			try (JarFile j = new JarFile(jarPath.toFile())) {
				j.stream().filter(je -> je.getName().endsWith(".class")).forEach(je -> {
					String n = je.getName();
					int lastSlash = n.lastIndexOf('/');
					s.add(lastSlash > 0 ? n.substring(0, lastSlash).replace('/', '.') : "");
				});
			}
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * compile a source bundle if it's out of sync
	 * 
	 * @param sbi the bundle info
	 * @param writer where to write issues
	 * @throws OSGiException if bundle operations fail
	 * @throws IOException if there are issues with the contents of the bundle
	 * @return the activated bundle
	 * @throws InterruptedException if interrupted while waiting for bundle state change
	 */
	public boolean compileSourceBundle(SourceBundleInfo sbi, PrintWriter writer)
			throws OSGiException, IOException, InterruptedException {
		if (writer == null) {
			writer = new NullPrintWriter();
		}

		boolean needsCompile = false;

		sbi.updateFromFilesystem(writer);

		int failing = sbi.getFailingSourcesCount();
		int newSourcecount = sbi.getNewSourcesCount();

		long lastBundleActivation = 0; // XXX record last bundle activation in bundlestatusmodel
		if (failing > 0 && (lastBundleActivation > sbi.getLastCompileAttempt())) {
			needsCompile = true;
		}

		if (newSourcecount == 0) {
			if (failing > 0) {
				writer.printf("%s hasn't changed, with %d file%s failing in previous build(s):\n",
					sbi.getSourceDir().toString(), failing, failing > 1 ? "s" : "");
				writer.printf("%s\n", sbi.getPreviousBuildErrors());
			}
			if (sbi.newManifestFile()) {
				needsCompile = true;
			}
		}
		else {
			needsCompile = true;
		}

		if (needsCompile) {
			writer.printf("%d new files, %d skipped, %s\n", newSourcecount, failing,
				sbi.newManifestFile() ? ", new manifest" : "");

			// if there a bundle is currently active, uninstall it
			Bundle b = sbi.getBundle();
			if (b != null) {
				deactivateSynchronously(b);
			}

			// once we've committed to recompile and regenerate generated classes, delete the old stuff
			sbi.deleteOldBinaries();

			BundleCompiler bundleCompiler = new BundleCompiler(this);

			long startTime = System.nanoTime();
			bundleCompiler.compileToExplodedBundle(sbi, writer);
			long endTime = System.nanoTime();
			writer.printf("%3.2f seconds compile time.\n", (endTime - startTime) / 1e9);
			fireSourceBundleCompiled(sbi);
			return true;
		}
		return false;
	}

	List<OSGiListener> osgiListeners = new ArrayList<>();

	void fireSourceBundleCompiled(SourceBundleInfo sbi) {
		synchronized (osgiListeners) {
			for (OSGiListener l : osgiListeners) {
				l.sourceBundleCompiled(sbi);
			}
		}
	}

	void fireBundleActivationChange(Bundle b, boolean newActivation) {
		synchronized (osgiListeners) {
			for (OSGiListener l : osgiListeners) {
				l.bundleActivationChange(b, newActivation);
			}
		}
	}

	public void addListener(OSGiListener osgiListener) {
		synchronized (osgiListeners) {
			osgiListeners.add(osgiListener);
		}
	}

	public void removeListener(OSGiListener osgiListener) {
		synchronized (osgiListeners) {
			osgiListeners.remove(osgiListener);
		}
	}

}
