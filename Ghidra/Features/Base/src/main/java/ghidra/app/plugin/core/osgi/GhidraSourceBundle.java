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

import static java.util.stream.Collectors.*;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.tools.*;
import javax.tools.JavaFileObject.Kind;

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleException;
import org.osgi.framework.Constants;
import org.osgi.framework.wiring.BundleRequirement;
import org.osgi.framework.wiring.BundleWiring;
import org.phidias.compile.BundleJavaManager;

import aQute.bnd.osgi.*;
import aQute.bnd.osgi.Clazz.QUERY;
import generic.io.NullPrintWriter;
import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.util.Msg;

/**
 * {@link GhidraSourceBundle} represents a Java source directory that is compiled on build to an OSGi bundle.
 * 
 * A manifest and BundleActivator are generated if not already present.
 */
public class GhidraSourceBundle extends GhidraBundle {
	private static final String GENERATED_ACTIVATOR_CLASSNAME = "GeneratedActivator";
	private static final Predicate<String> isClassFile =
		Pattern.compile("(\\$.*)?\\.class", Pattern.CASE_INSENSITIVE).asMatchPredicate();

	protected interface DiscrepencyCallback {
		/**
		 * Invoked when there is a discrepancy between {@code sourceFile} and its
		 * corresponding class file(s), {@code classFiles}
		 * 
		 * @param sourceFile the source file or null to indicate the class files have no corresponding source
		 * @param classFiles corresponding class files(s)
		 * @throws Throwable an exception
		 */
		void found(ResourceFile sourceFile, Collection<Path> classFiles) throws Throwable;
	}

	private final String symbolicName;
	private final Path binDir;
	private final String bundleLoc;

	private final List<ResourceFile> newSources = new ArrayList<>();
	private final List<Path> oldBin = new ArrayList<>();

	private JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();

	//// information indexed by source file

	private final HashMap<ResourceFile, GhidraBundle.BuildFailure> buildErrors = new HashMap<>();
	private final HashMap<ResourceFile, List<BundleRequirement>> sourceFileToRequirements =
		new HashMap<>();
	private final HashMap<String, List<ResourceFile>> requirementToSourceFileMap = new HashMap<>();

	private long lastCompileAttempt;

	/**
	 * Create a new GhidraSourceBundle.
	 * 
	 * @param bundleHost the {@link BundleHost} instance this bundle will belong to
	 * @param sourceDirectory the source bundle directory
	 * @param enabled true to start enabled
	 * @param systemBundle true if this is a Ghidra system bundle
	 */
	public GhidraSourceBundle(BundleHost bundleHost, ResourceFile sourceDirectory, boolean enabled,
			boolean systemBundle) {
		super(bundleHost, sourceDirectory, enabled, systemBundle);

		this.symbolicName = GhidraSourceBundle.sourceDirHash(path);
		this.binDir = GhidraSourceBundle.getCompiledBundlesDir().resolve(symbolicName);

		this.bundleLoc = "reference:file://" + binDir.toAbsolutePath().normalize().toString();
	}

	/**
	 * Source bundles are compiled to a path relative to the user's home:  
	 * &nbsp;{@code $USERHOME/.ghidra/.ghidra_<ghidra version>/osgi/compiled-bundles/<sourceDirHash> }
	 *  
	 * @return the destination for compiled source bundles
	 *
	 * @see BundleHost#getOsgiDir
	 */
	public static Path getCompiledBundlesDir() {
		return BundleHost.getOsgiDir().resolve("compiled-bundles");
	}

	/**
	 * When a source bundle doesn't have a manifest, Ghidra computes the bundle's 
	 * symbolic name as a hash of the source directory path.
	 * 
	 * The hash is is also used as the final path component of the compile destination:<br/>
	 * &nbsp;{@code $USERHOME/.ghidra/.ghidra_<ghidra version>/osgi/compiled-bundles/<sourceDirHash> }
	 * 
	 * @param sourceDir the source directory
	 * @return a string hash of the source directory path
	 * 
	 * @see #getCompiledBundlesDir
	 */
	public static String sourceDirHash(ResourceFile sourceDir) {
		return Integer.toHexString(sourceDir.getAbsolutePath().hashCode());
	}

	/**
	 * for testing only!!!
	 * 
	 * @param sourceFile a ghidra script file
	 * @return the directory its class is compiled to
	 */
	public static Path getBindirFromScriptFile(ResourceFile sourceFile) {
		ResourceFile tmpSourceDir = sourceFile.getParentFile();
		String tmpSymbolicName = GhidraSourceBundle.sourceDirHash(tmpSourceDir);
		return GhidraSourceBundle.getCompiledBundlesDir().resolve(tmpSymbolicName);
	}

	/**
	 * Returen the class name corresponding to a script in this source bundle.
	 * 
	 * @param sourceFile a source file from this bundle
	 * @return the class name
	 */
	public String classNameForScript(ResourceFile sourceFile) {
		String p;
		try {
			p = sourceFile.getCanonicalPath();
			p = p.substring(1 + path.getCanonicalPath().length(), p.length() - 5);// relative path less ".java"
			return p.replace(File.separatorChar, '.');
		}
		catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	void buildSuccess(ResourceFile sourceFile) {
		buildErrors.remove(sourceFile);
	}

	/**
	 * append build error 
	 * @param sourceFile the file w/ errors 
	 * @param err an error string
	 */
	void buildError(ResourceFile sourceFile, String err) {
		GhidraBundle.BuildFailure f =
			buildErrors.computeIfAbsent(sourceFile, x -> new GhidraBundle.BuildFailure());
		f.when = sourceFile.lastModified();
		f.message.append(err);
	}

	/**
	 * get any errors associated with building the given source file.
	 * 
	 * @param sourceFile the source file
	 * @return a {@link GhidraBundle.BuildFailure} object
	 */
	public GhidraBundle.BuildFailure getErrors(ResourceFile sourceFile) {
		return buildErrors.get(sourceFile);
	}

	private String getPreviousBuildErrors() {
		return buildErrors.values()
			.stream()
			.map(e -> e.message.toString())
			.collect(Collectors.joining());
	}

	private String parseImports(ResourceFile javaSource) {
		return GhidraScriptUtil.newScriptInfo(javaSource).getImportPackage();
	}

	/**
	 * update buildReqs based on \@importpackages tag in java files in the default(unnamed) package
	 * 
	 * @throws GhidraBundleException on failure to parse the \@importpackages tag
	 */
	private void updateRequirementsFromMetadata() throws GhidraBundleException {
		sourceFileToRequirements.clear();
		requirementToSourceFileMap.clear();

		for (ResourceFile file : path.listFiles()) {
			if (file.getName().endsWith(".java")) {
				// without GhidraScriptComponentProvider.updateAvailableScriptFilesForDirectory, or GhidraScriptComponentProvider.newScript
				// this might be the earliest need for ScriptInfo, so allow construction.

				// NB: ScriptInfo will update field values if lastModified has changed since last time they were computed
				String imps = parseImports(file);
				if (imps != null && !imps.isEmpty()) {
					List<BundleRequirement> requirements;
					try {
						requirements = OSGiUtils.parseImports(imps);
					}
					catch (BundleException e) {
						throw new GhidraBundleException(getBundleLocation(), "parsing manifest", e);
					}
					sourceFileToRequirements.put(file, requirements);
					for (BundleRequirement requirement : requirements) {
						requirementToSourceFileMap
							.computeIfAbsent(requirement.toString(), x -> new ArrayList<>())
							.add(file);
					}
				}
			}
		}
	}

	private Map<String, BundleRequirement> getComputedReqs() {
		Map<String, BundleRequirement> dedupedReqs = new HashMap<>();
		sourceFileToRequirements.values()
			.stream()
			.flatMap(List::stream)
			.forEach(r -> dedupedReqs.putIfAbsent(r.toString(), r));

		return dedupedReqs;
	}

	@Override
	public List<BundleRequirement> getAllRequirements() {
		try {
			updateRequirementsFromMetadata();
		}
		catch (GhidraBundleException e) {
			throw new RuntimeException(e);
		}
		Map<String, BundleRequirement> reqs = getComputedReqs();
		// insert requirements from a source manifest
		ResourceFile manifest = getSourceManifestPath();
		if (manifest.exists()) {
			try {
				Manifest m = new Manifest(manifest.getInputStream());
				String imports = m.getMainAttributes().getValue("Import-Package");
				for (BundleRequirement r : OSGiUtils.parseImports(imports)) {
					reqs.putIfAbsent(r.toString(), r);
				}
			}
			catch (IOException | BundleException e) {
				throw new RuntimeException(e);
			}
		}
		return new ArrayList<>(reqs.values());
	}

	/**
	 * look for new sources, metadata, manifest file.
	 * 
	 * if files had errors last time, haven't changed, and no new requirements are available, remove them.
	 * 
	 * @param writer for reporting status to user
	 * @throws IOException while accessing manifest file
	 * @throws OSGiException while parsing imports
	 */
	void updateNewSourceOldBinFromFilesystem(PrintWriter writer) throws IOException, OSGiException {
		// look for new source files
		newSources.clear();
		oldBin.clear();

		visitDiscrepencies((sf, bfs) -> {
			if (sf != null) {
				newSources.add(sf);
			}
			if (bfs != null) {
				oldBin.addAll(bfs);
			}
		});

		// don't rebuild source files that failed last time and haven't changed
		Iterator<ResourceFile> it = newSources.iterator();
		while (it.hasNext()) {
			ResourceFile sf = it.next();
			GhidraBundle.BuildFailure f = buildErrors.get(sf);
			if (f != null) {
				if (f.when == sf.lastModified()) {
					it.remove();
					continue;
				}
				// it's either new or worth trying again
				buildErrors.remove(sf);
			}
		}
	}

	private void deleteOldBinaries() throws IOException {
		// dedupe and omit files that don't exist
		oldBin.sort(null);
		Iterable<Path> paths = () -> oldBin.stream().distinct().filter(Files::exists).iterator();

		for (Path bf : paths) {
			Files.delete(bf);
		}
		// oldBin.clear();
	}

	int getFailingSourcesCount() {
		return buildErrors.size();
	}

	int getNewSourcesCount() {
		return newSources.size();
	}

	/**
	 * used just after {@link #build} to get the newly compiled source files 
	 * @return new source files
	 */
	public List<ResourceFile> getNewSources() {
		return newSources;
	}

	void compileAttempted() {
		lastCompileAttempt = System.currentTimeMillis();
	}

	long getLastCompileAttempt() {
		return lastCompileAttempt;
	}

	@Override
	public String getBundleLocation() {
		return bundleLoc;
	}

	ResourceFile getSourceManifestPath() {
		return new ResourceFile(path, "META-INF" + File.separator + "MANIFEST.MF");
	}

	boolean hasNewManifest() throws IOException {
		ResourceFile smf = getSourceManifestPath();
		Path dmf = binDir.resolve("META-INF").resolve("MANIFEST.MF");

		return smf.exists() && (Files.notExists(dmf) ||
			smf.lastModified() > Files.getLastModifiedTime(dmf).toMillis());
	}

	protected static boolean wipeContents(Path path) throws IOException {
		if (Files.exists(path)) {
			boolean anythingDeleted = false;
			for (Path p : (Iterable<Path>) Files.walk(path)
				.sorted(Comparator.reverseOrder())::iterator) {
				anythingDeleted |= Files.deleteIfExists(p);
			}
			return anythingDeleted;
		}
		return false;
	}

	private boolean wipeBinDir() throws IOException {
		return wipeContents(binDir);
	}

	@Override
	public boolean build(PrintWriter writer) throws Exception {
		if (writer == null) {
			writer = new NullPrintWriter();
		}

		boolean needsCompile = false;

		// look for a manifest before checking other files
		boolean newManifest = hasNewManifest();
		if (newManifest) {
			wipeBinDir();
		}

		updateNewSourceOldBinFromFilesystem(writer);
		updateRequirementsFromMetadata();

		// if previous failures now resolve, try again
		for (ResourceFile sf : buildErrors.keySet()) {
			List<BundleRequirement> reqs = sourceFileToRequirements.get(sf);
			if (reqs != null && !reqs.isEmpty() && bundleHost.canResolveAll(reqs)) {
				if (!newSources.contains(sf)) {
					newSources.add(sf);
				}
				for (ResourceFile oldbin : correspondingBinaries(sf)) {
					oldbin.delete();
				}
			}
		}
		// if previous successes no longer resolve, (cleanup) and try again
		for (Entry<ResourceFile, List<BundleRequirement>> e : sourceFileToRequirements.entrySet()) {
			ResourceFile sf = e.getKey();
			List<BundleRequirement> reqs = e.getValue();
			if (reqs != null && !reqs.isEmpty() && !buildErrors.containsKey(sf) &&
				!bundleHost.canResolveAll(reqs)) {
				if (!newSources.contains(sf)) {
					newSources.add(sf);
				}

				Arrays.stream(correspondingBinaries(sf))
					.map(rf -> rf.getFile(false).toPath())
					.forEach(oldBin::add);
			}
		}

		int failuresLastTime = getFailingSourcesCount();
		int newSourceCount = getNewSourcesCount();

		if (newSourceCount == 0) {
			if (failuresLastTime > 0) {
				writer.printf("%s hasn't changed, with %d file%s failing in previous build(s):\n",
					path.toString(), failuresLastTime, failuresLastTime > 1 ? "s" : "");
				writer.printf("%s\n", getPreviousBuildErrors());
			}
		}
		else {
			needsCompile = true;
		}

		// finally, we should be able to handle empty directories
		if (!binDir.toFile().exists()) {
			needsCompile = true;
		}

		if (needsCompile) {
			// if there is a bundle at our locations, uninstall it
			Bundle b = bundleHost.getOSGiBundle(getBundleLocation());
			if (b != null) {
				bundleHost.deactivateSynchronously(b);
			}

			// once we've committed to recompile and regenerate generated classes, delete the old stuff
			deleteOldBinaries();

			String summary = compileToExplodedBundle(writer);
			bundleHost.notifyBundleBuilt(this, summary);
			return true;
		}
		return false;
	}

	@Override
	public boolean clean() {
		boolean anythingChanged = false;
		if (!buildErrors.isEmpty()) {
			buildErrors.clear();
			anythingChanged |= true;
		}

		try {
			Bundle b = getOSGiBundle();
			if (b != null) {
				bundleHost.deactivateSynchronously(b);
			}
			return anythingChanged | wipeBinDir();
		}
		catch (IOException | GhidraBundleException | InterruptedException e) {
			Msg.showError(this, null, "source bundle clean error",
				"while attempting to delete the compiled directory, an exception was thrown", e);
		}
		return anythingChanged;
	}

	private ResourceFile[] correspondingBinaries(ResourceFile source) {
		String parentPath = source.getParentFile().getAbsolutePath();
		String relpath = parentPath.substring(path.getAbsolutePath().length());
		if (relpath.startsWith(File.separator)) {
			relpath = relpath.substring(1);
		}
		String n0 = source.getName();
		final String n = n0.substring(0, n0.length() - 5);// trim .java
		ResourceFile bp = new ResourceFile(binDir.resolve(relpath).toFile());
		if (!bp.exists() || !bp.isDirectory()) {
			return new ResourceFile[] {};
		}
		return bp.listFiles(f -> {
			String nn = f.getName();
			return nn.startsWith(n) && isClassFile.test(nn.substring(n.length()));
		});
	}

	/**
	 * <pre>
	 * walk resources to find:
	 *  - source files that are newer than their corresponding binary
	 *		reports (source file, list of corresponding binaries)
	 * 	- source files with no corresponding binary
	 *		reports (source file, <empty list>)
	 *  - binary files with no corresponding source
	 *  	reports (null, list of binary files)
	 *  
	 *   for a source file source_root/com/blah/Blah.java
	 *   
	 *   all of the following binaries would correspond:
	 *   	binary_root/com/blah/Blah.class
	 *   	binary_root/com/blah/Blah$Inner.class
	 *   	binary_root/com/blah/Blah$12.class
	 *   	binary_root/com/blah/Blah$12.class
	 *   	binary_root/com/blah/Blah$Inner$Innerer.class
	 *   	...
	 * </pre>
	 * @param cb callback
	 */
	protected void visitDiscrepencies(DiscrepencyCallback cb) {
		try {
			Deque<ResourceFile> stack = new ArrayDeque<>();
			stack.add(path);
			while (!stack.isEmpty()) {
				ResourceFile sd = stack.pop();
				String relpath = sd.getAbsolutePath().substring(path.getAbsolutePath().length());
				if (relpath.startsWith(File.separator)) {
					relpath = relpath.substring(1);
				}
				Path bd = binDir.resolve(relpath);

				// index the class files in the corresponding directory by basename
				Map<String, List<Path>> binfiles = Files.exists(bd) ? Files.list(bd)
					.filter(x -> Files.isRegularFile(x) &&
						x.getFileName().toString().endsWith(".class"))
					.collect(groupingBy(x -> {
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
							long sourceLastModified = sf.lastModified();
							List<Path> bfs = binfiles.remove(n.substring(0, n.length() - 5));
							long binaryLastModified = (bfs == null || bfs.isEmpty()) ? -1
									: bfs.stream()
										.mapToLong(bf -> bf.toFile().lastModified())
										.min()
										.getAsLong();
							// if source is newer than the oldest binary, report
							if (sourceLastModified > binaryLastModified) {
								cb.found(sf, bfs);
							}
						}
					}
				}
				// any remaining .class files are missing .java files
				if (!binfiles.isEmpty()) {
					cb.found(null,
						binfiles.values()
							.stream()
							.flatMap(l -> l.stream())
							.collect(Collectors.toList()));
				}
			}
		}
		catch (Throwable t) {
			t.printStackTrace();
		}
	}

	private static class Summary {
		static String SEP = ", ";
		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new PrintWriter(sw, true);

		void printf(String format, Object... args) {
			if (sw.getBuffer().length() > 0) {
				pw.write(SEP);
			}
			pw.printf(format, args);
		}

		void print(String arg) {
			pw.print(arg);
		}

		String getValue() {
			pw.flush();
			return sw.getBuffer().toString();
		}

	}

	/**
	 *  compile a source directory to an exploded bundle
	 *  
	 * @param writer for updating the user during compilation
	 * @throws IOException for source/manifest file reading/generation and binary deletion/creation
	 * @throws OSGiException if generation of bundle metadata fails
	 */
	private String compileToExplodedBundle(PrintWriter writer) throws IOException, OSGiException {
		compileAttempted();

		Files.createDirectories(binDir);

		Summary summary = new Summary();

		List<String> options = new ArrayList<>();
		options.add("-g");
		options.add("-d");
		options.add(binDir.toString());
		options.add("-sourcepath");
		options.add(path.toString());
		options.add("-classpath");
		options.add(System.getProperty("java.class.path") + File.pathSeparator + binDir.toString());
		options.add("-proc:none");

		final ResourceFileJavaFileManager resourceFileJavaManager =
			new ResourceFileJavaFileManager(Collections.singletonList(path), buildErrors.keySet());

		BundleJavaManager bundleJavaManager =
			new BundleJavaManager(bundleHost.getHostFramework(), resourceFileJavaManager, options);
		// The phidias BundleJavaManager is for compiling from within a bundle -- it makes the
		// bundle dependencies available to the compiler classpath.  Here, we are compiling in an as-yet 
		// non-existing bundle, so we forge the wiring based on @importpackages metadata.

		// XXX skip this if there's a source manifest, emit warnings about @importpackages
		// get wires for currently active bundles to satisfy all requirements
		List<BundleRequirement> reqs = getAllRequirements();
		List<BundleWiring> bundleWirings = bundleHost.resolve(reqs);

		if (!reqs.isEmpty()) {
			writer.printf("%d import requirement%s remain%s unresolved:\n", reqs.size(),
				reqs.size() > 1 ? "s" : "", reqs.size() > 1 ? "" : "s");
			for (BundleRequirement req : reqs) {
				writer.printf("  %s\n", req.toString());
			}

			summary.printf("%d missing @import%s:%s", reqs.size(), reqs.size() > 1 ? "s" : "",
				reqs.stream()
					.flatMap(r -> OSGiUtils.extractPackageNamesFromFailedResolution(r.toString()).stream())
					.distinct()
					.collect(Collectors.joining(",")));
		}
		// send the capabilities to phidias
		bundleWirings.forEach(bundleJavaManager::addBundleWiring);

		final List<ResourceFileJavaFileObject> sourceFiles = newSources.stream()
			.map(sf -> new ResourceFileJavaFileObject(sf.getParentFile(), sf, Kind.SOURCE))
			.collect(Collectors.toList());

		Path dmf = binDir.resolve("META-INF").resolve("MANIFEST.MF");
		if (Files.exists(dmf)) {
			Files.delete(dmf);
		}

		// try to compile, if we fail, avoid offenders and try again
		while (!sourceFiles.isEmpty()) {
			DiagnosticCollector<JavaFileObject> diagnostics =
				new DiagnosticCollector<JavaFileObject>();
			JavaCompiler.CompilationTask task = compiler.getTask(writer, bundleJavaManager,
				diagnostics, options, null, sourceFiles);
			// task.setProcessors // for annotation processing / code generation

			Boolean successfulCompilation = task.call();
			if (successfulCompilation) {
				break;
			}
			Set<ResourceFileJavaFileObject> hadErrors = new HashSet<>();
			for (Diagnostic<? extends JavaFileObject> d : diagnostics.getDiagnostics()) {
				String err = d.toString() + "\n";
				writer.write(err);
				ResourceFileJavaFileObject sf = (ResourceFileJavaFileObject) d.getSource();
				ResourceFile rf = sf.getFile();
				buildError(rf, err); // remember all errors for this file
				hadErrors.add(sf);
			}
			for (ResourceFileJavaFileObject sf : hadErrors) {
				if (sourceFiles.remove(sf)) {
					writer.printf("skipping %s\n", sf.getFile().toString());
				}
				else {
					throw new IOException(
						"compilation error loop condition for " + sf.getFile().toString());
				}
			}

		}
		// mark the successful compilations
		for (ResourceFileJavaFileObject sf : sourceFiles) {
			ResourceFile rf = sf.getFile();
			buildSuccess(rf);
		}
		// buildErrors is now up to date, set status
		if (getFailingSourcesCount() > 0) {
			summary.printf("%d failing source files", getFailingSourcesCount());
		}

		ResourceFile smf = getSourceManifestPath();
		if (smf.exists()) {
			Files.createDirectories(dmf.getParent());
			Files.copy(smf.getInputStream(), dmf, StandardCopyOption.REPLACE_EXISTING);
			return summary.getValue();
		}

		// no manifest, so create one with bndtools
		Analyzer analyzer = new Analyzer();
		analyzer.setJar(new Jar(binDir.toFile())); // give bnd the contents
		analyzer.setProperty("Bundle-SymbolicName", GhidraSourceBundle.sourceDirHash(path));
		analyzer.setProperty("Bundle-Version", "1.0");
		// XXX we must constrain analyzed imports according to constraints declared in @importpackages tags
		analyzer.setProperty("Import-Package", "*");
		analyzer.setProperty("Export-Package", "!*.private.*,!*.internal.*,*");
		// analyzer.setBundleActivator(s);

		try {
			Manifest manifest;
			try {
				manifest = analyzer.calcManifest();
			}
			catch (Exception e) {
				summary.print("bad manifest");
				throw new OSGiException("failed to calculate manifest by analyzing code", e);
			}
			Attributes ma = manifest.getMainAttributes();

			String activatorClassName = null;
			try {
				for (Clazz clazz : analyzer.getClassspace().values()) {
					if (clazz.is(QUERY.IMPLEMENTS,
						new Instruction("org.osgi.framework.BundleActivator"), analyzer)) {
						System.err.printf("found BundleActivator class %s\n", clazz);
						activatorClassName = clazz.toString();
					}
				}
			}
			catch (Exception e) {
				summary.print("failed bnd analysis");
				throw new OSGiException("failed to query classes while searching for activator", e);
			}
			if (activatorClassName == null) {
				activatorClassName = GENERATED_ACTIVATOR_CLASSNAME;
				if (!buildDefaultActivator(binDir, activatorClassName, writer)) {
					summary.print("failed to build generated activator");
					return summary.getValue();
				}
				// since we add the activator after bndtools built the imports, we should add its imports too
				String imps = ma.getValue(Constants.IMPORT_PACKAGE);
				if (imps == null) {
					ma.putValue(Constants.IMPORT_PACKAGE,
						GhidraBundleActivator.class.getPackageName());
				}
				else {
					ma.putValue(Constants.IMPORT_PACKAGE,
						imps + "," + GhidraBundleActivator.class.getPackageName());
				}
			}
			ma.putValue(Constants.BUNDLE_ACTIVATOR, activatorClassName);

			// write the manifest
			Files.createDirectories(dmf.getParent());
			try (OutputStream out = Files.newOutputStream(dmf)) {
				manifest.write(out);
			}
		}
		finally {
			analyzer.close();
		}
		return summary.getValue();
	}

	/**
	 * create and compile a default bundle activator
	 * 
	 * @param bindir destination for class file
	 * @param activatorClassName the name to use for the genearted activator class
	 * @param writer for writing compile errors
	 * @return true if compilation succeeded
	 * @throws IOException for failed write of source/binary activator
	 */
	private boolean buildDefaultActivator(Path bindir, String activatorClassName, Writer writer)
			throws IOException {
		Path activatorSourceFileName = bindir.resolve(activatorClassName + ".java");

		try (PrintWriter activatorWriter = new PrintWriter(
			Files.newBufferedWriter(activatorSourceFileName, Charset.forName("UTF-8")))) {
			activatorWriter.println("import " + GhidraBundleActivator.class.getName() + ";");
			activatorWriter.println("import org.osgi.framework.BundleActivator;");
			activatorWriter.println("import org.osgi.framework.BundleContext;");
			activatorWriter.println("public class " + GENERATED_ACTIVATOR_CLASSNAME +
				" extends GhidraBundleActivator {");
			activatorWriter.println("  protected void start(BundleContext bc, Object api) {");
			activatorWriter.println("    // TODO: stuff to do on bundle start");
			activatorWriter.println("  }");
			activatorWriter.println("  protected void stop(BundleContext bc, Object api) {");
			activatorWriter.println("    // TODO: stuff to do on bundle stop");
			activatorWriter.println("  }");
			activatorWriter.println();
			activatorWriter.println("}");
		}

		List<String> options = new ArrayList<>();
		options.add("-g");
		options.add("-d");
		options.add(bindir.toString());
		options.add("-sourcepath");
		options.add(bindir.toString());
		options.add("-classpath");
		options.add(System.getProperty("java.class.path"));
		options.add("-proc:none");

		StandardJavaFileManager javaFileManager = compiler.getStandardFileManager(null, null, null);
		BundleJavaManager bundleJavaManager =
			new BundleJavaManager(bundleHost.getHostFramework(), javaFileManager, options);
		Iterable<? extends JavaFileObject> sourceFiles =
			javaFileManager.getJavaFileObjectsFromPaths(List.of(activatorSourceFileName));
		DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<JavaFileObject>();
		JavaCompiler.CompilationTask task =
			compiler.getTask(writer, bundleJavaManager, diagnostics, options, null, sourceFiles);
		if (!task.call()) {
			for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
				writer.write(
					diagnostic.getSource().toString() + ": " + diagnostic.getMessage(null) + "\n");
			}
			return false;
		}
		return true;
	}

}
