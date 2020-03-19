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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.felix.framework.FrameworkFactory;
import org.apache.felix.framework.util.FelixConstants;
import org.apache.felix.framework.util.manifestparser.ManifestParser;
import org.apache.felix.main.AutoProcessor;
import org.osgi.framework.*;
import org.osgi.framework.launch.Framework;
import org.osgi.framework.wiring.*;
import org.osgi.service.log.*;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.ScriptInfo;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

// XXX this class should be part of a service/plugin
public class BundleHost {
	static public String getSymbolicNameFromSourceDir(ResourceFile sourceDir) {
		return Integer.toHexString(sourceDir.getAbsolutePath().hashCode());
	}

	public void dispose() {
		if (felix != null) {
			stop_felix();
		}
	}

	// XXX this should be remembered in savestate
	HashMap<ResourceFile, SourceBundleInfo> file2sbi = new HashMap<>();

	public SourceBundleInfo getSourceBundleInfo(ResourceFile sourceDir) {
		return file2sbi.computeIfAbsent(sourceDir, SourceBundleInfo::new);
	}

	// XXX consumers should clean up after themselves
	public void removeSourceBundleInfo(ResourceFile sourceDir) {
		file2sbi.remove(sourceDir);
	}

	/**
	 * parse Import-Package string from a bundle manifest
	 * 
	 * @param imports Import-Package value
	 * @return deduced requirements or null if there was an error
	 * @throws BundleException on failed parse
	 */
	static List<BundleRequirement> parseImports(String imports) throws BundleException {

		// parse it with Felix's ManifestParser to a list of BundleRequirement objects
		Map<String, Object> headerMap = new HashMap<>();
		headerMap.put(Constants.IMPORT_PACKAGE, imports);
		ManifestParser mp;
		mp = new ManifestParser(null, null, null, headerMap);
		return mp.getRequirements();
	}

	/**
	 * cache of data corresponding to a source directory that is bound to be an exploded bundle
	 */
	protected static class BuildFailure {
		long when = -1;
		StringBuilder message = new StringBuilder();
	}

	public class SourceBundleInfo {
		final private ResourceFile sourceDir;
		final String symbolicName;
		final private Path binDir;
		final private String bundleLoc;

		//// information indexed by source file

		// XXX add separate missing requirements tracking
		final HashMap<ResourceFile, BuildFailure> buildErrors = new HashMap<>();

		// cached values parsed form @imports tags on default-package source files

		public SourceBundleInfo(ResourceFile sourceDir) {
			this.sourceDir = sourceDir;
			this.symbolicName = getSymbolicNameFromSourceDir(sourceDir);
			this.binDir = BundleHost.this.getCompiledBundlesDir().resolve(symbolicName);

			this.bundleLoc =
				"reference:file://" + getBinDir().toAbsolutePath().normalize().toString();

		}

		public String classNameForScript(ResourceFile sourceFile) {
			String p;
			try {
				p = sourceFile.getCanonicalPath();
				p = p.substring(1 + getSourceDir().getCanonicalPath().length(), p.length() - 5);// relative path less ".java"
				return p.replace(File.separatorChar, '.');
			}
			catch (IOException e) {
				e.printStackTrace();
				return null;
			}
		}

		public Bundle getBundle() {
			return BundleHost.this.getBundle(getBundleLoc());
		}

		public String getBundleLoc() {
			return bundleLoc;
		}

		public ResourceFile getSourceDir() {
			return sourceDir;
		}

		public Path getBinDir() {
			return binDir;
		}

		public Bundle install() throws BundleException {
			return BundleHost.this.bc.installBundle(getBundleLoc());
		}

		public void buildError(ResourceFile rf, String err) {
			BuildFailure f = buildErrors.computeIfAbsent(rf, x -> new BuildFailure());
			f.when = rf.lastModified();
			f.message.append(err);
		}

		public String getPreviousBuildErrors() {
			return buildErrors.values().stream().map(e -> e.message.toString()).collect(
				Collectors.joining());
		}

		/**
		 * check for build errors from last time
		 * @param rf file to test
		 * @return true if this file had errors and hasn't changed
		 */
		private boolean syncBuildErrors(ResourceFile rf) {
			BuildFailure f = buildErrors.get(rf);
			if (f != null) {
				if (f.when == rf.lastModified()) {
					return true;
				}
				buildErrors.remove(rf);
			}
			return false;
		}

		public List<BundleRequirement> getRequirements() {
			return foundRequirements;
		}

		final List<ResourceFile> newSources = new ArrayList<>();
		List<Path> oldBin = new ArrayList<>();

		boolean foundNewManifest;
		private List<BundleRequirement> foundRequirements;

		private void computeRequirements() throws BundleException {
			foundRequirements = null;
			Map<String, BundleRequirement> dedupedreqs = new HashMap<>();
			// parse metadata from all Java source in sourceDir
			for (ResourceFile rf : sourceDir.listFiles()) {
				if (rf.getName().endsWith(".java")) {
					// NB: ScriptInfo will update field values if lastModified has changed since last time they were computed
					ScriptInfo si = GhidraScriptUtil.getScriptInfo(rf);
					String imps = si.getImports();
					if (imps != null && !imps.isEmpty()) {
						for (BundleRequirement req : BundleHost.parseImports(imps)) {
							dedupedreqs.put(req.toString(), req);
						}
					}
				}
			}
			foundRequirements = new ArrayList<>(dedupedreqs.values());
		}

		/**
		 * look for new sources, metadata, manifest file.
		 * 
		 * @param writer for reporting status to user
		 * @throws IOException when there are unexpected issues w/ the filesystem
		 */
		public void udpateFromFilesystem(PrintWriter writer) throws IOException {

			// look for new source files
			newSources.clear();
			oldBin.clear();
			ResourceFile smf =
				new ResourceFile(getSourceDir(), "META-INF" + File.separator + "MANIFEST.MF");
			Path dmf = getBinDir().resolve("META-INF").resolve("MANIFEST.MF");

			foundNewManifest = smf.exists() && (Files.notExists(dmf) ||
				smf.lastModified() > Files.getLastModifiedTime(dmf).toMillis());

			BundleHost.visitDiscrepencies(getSourceDir(), getBinDir(), (sf, bfs) -> {
				if (sf != null) {
					newSources.add(sf);
				}
				if (bfs != null) {
					oldBin.addAll(bfs);
				}
			});

			try {
				computeRequirements();
			}
			catch (BundleException e) {
				Msg.error(this, "computing requirements", e);
				e.printStackTrace(writer);
				return;
			}

			// remove source files that failed last time and haven't changed 
			Iterator<ResourceFile> it = newSources.iterator();
			while (it.hasNext()) {
				ResourceFile sf = it.next();
				if (syncBuildErrors(sf)) {
					it.remove();
				}
			}
		}

		public void deleteOldBinaries() throws IOException {
			for (Path bf : oldBin) {
				Files.delete(bf);
			}
			// oldBin.clear();
		}

		public int getFailingSourcesCount() {
			return buildErrors.size();
		}

		public int getNewSourcesCount() {
			return newSources.size();
		}

		public List<ResourceFile> getNewSources() {
			return newSources;
		}

		public boolean newManifestFile() {
			return foundNewManifest;
		}

	}

	String buildExtraPackages() {
		Set<String> packages = new HashSet<>();
		getPackagesFromClasspath(packages);
		return packages.stream().collect(Collectors.joining(","));
	}

	BundleContext bc;
	Framework felix;
	Bundle fileinstall_bundle;

	Bundle installFromPath(String path_to_jar) throws BundleException {
		Path p = Paths.get(path_to_jar);
		return bc.installBundle("file://" + p.toAbsolutePath().normalize().toString());
	}

	Bundle installFromPathAs(String path_to_jar, String location)
			throws FileNotFoundException, IOException, BundleException {
		return bc.installBundle(location, new FileInputStream(new File(path_to_jar)));
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

	public void start_felix() throws BundleException, IOException {

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

		config.setProperty("felix.fileinstall.dir", getWatchedBundleDirs());
		// config.setProperty("felix.fileinstall.log.level", "999");
		// config.setProperty("felix.fileinstall.log.default", "jul"); // stdout
		config.setProperty("felix.fileinstall.bundles.new.start", "true"); // autostart bundles
		config.put(FelixConstants.LOG_LEVEL_PROP, "999");// was 4
		config.put(FelixConstants.LOG_LOGGER_PROP, new FelixLogger());

		FrameworkFactory factory = new FrameworkFactory();
		felix = factory.newFramework(config);

		felix.init();
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
				// System.err.printf("%s %s\n", event.getBundle(), event);
				switch (event.getType()) {
					case BundleEvent.INSTALLED:
						System.err.printf("INSTALLED %s\n", event.getBundle().getSymbolicName());
						break;
					case BundleEvent.UNINSTALLED:
						System.err.printf("UNINSTALLED %s\n", event.getBundle().getSymbolicName());
						break;
					case BundleEvent.STARTED:
						System.err.printf("STARTED %s\n", event.getBundle().getSymbolicName());
						break;
					case BundleEvent.STOPPED:
						System.err.printf("STOPPED %s\n", event.getBundle().getSymbolicName());
						break;
				}
			}
		});

		felix.start();
		// fileinstall_bundle = installFromPath(findJarForClass(FileInstall.class));
		// fileinstall_bundle.start();

	}

	private Path getOsgiDir() {
		Path usersettings = Application.getUserSettingsDirectory().toPath();
		return usersettings.resolve("osgi");
	}

	private String makeCacheDir() throws IOException {
		Path cache_dir = getOsgiDir().resolve("felixcache");
		Files.createDirectories(cache_dir);
		return cache_dir.toAbsolutePath().toString();
	}

	/** comma separated list of directories watched for bundles by fileinstaller */
	private String getWatchedBundleDirs() {
		return getCompiledBundlesDir().toAbsolutePath().toString();
	}

	public Path getCompiledBundlesDir() {
		return getOsgiDir().resolve("compiled-bundles");
	}

	public Bundle getBundle(String bundleLoc) {
		return bc.getBundle(bundleLoc);
	}

	// return true if it was running in the first place
	public boolean synchronousStop(Bundle b) throws InterruptedException, BundleException {
		if (b != null) {
			switch (b.getState()) {
				case Bundle.STARTING:
				case Bundle.ACTIVE:
					b.stop();
				case Bundle.STOPPING:
					while (true) {
						switch (b.getState()) {
							case Bundle.ACTIVE:
							case Bundle.STOPPING:
								Thread.sleep(500);
							default:
								return true;
						}
					}
				case Bundle.INSTALLED:
				case Bundle.RESOLVED:
				case Bundle.UNINSTALLED:
			}
		}
		return false;
	}

	public boolean synchronousUninstall(Bundle b) throws InterruptedException, BundleException {
		if (b != null) {
			if (b.getState() != Bundle.UNINSTALLED) {
				b.uninstall();
				while (true) {
					if (b.getState() == Bundle.UNINSTALLED) {
						return true;
					}
					Thread.sleep(500);
				}
			}
		}
		return false;
	}

	public boolean waitForBundleStart(String location)
			throws InterruptedException, BundleException {
		while (true) {
			Bundle b = bc.getBundle(location);
			if (b != null) {
				switch (b.getState()) {
					case Bundle.ACTIVE:
						return true;
					case Bundle.UNINSTALLED:
					case Bundle.STOPPING:
						return false;
					case Bundle.INSTALLED:
					case Bundle.RESOLVED:
						b.start();
						continue;
					case Bundle.STARTING:
				}
			}
			Thread.sleep(500);
		}
	}

	public void stop_felix() {
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

	public boolean stopBundleWatcher() {
		if (fileinstall_bundle != null) {
			try {
				fileinstall_bundle.stop();
				return true;
			}
			catch (BundleException e) {
				e.printStackTrace();
			}
		}
		return false;
	}

	public boolean startBundleWatcher() {
		if (fileinstall_bundle != null) {
			try {
				fileinstall_bundle.start();
				return true;
			}
			catch (BundleException e) {
				e.printStackTrace();
			}
		}
		return false;
	}

	public interface NewSourceCallback {
		void found(ResourceFile source_file, Collection<Path> class_files) throws Throwable;
	}

	public static void visitDiscrepencies(ResourceFile srcdir, Path bindir,
			NewSourceCallback new_source_cb) {
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

}
