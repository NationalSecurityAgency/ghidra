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
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.tools.*;
import javax.tools.JavaFileObject.Kind;

import org.apache.felix.framework.util.manifestparser.ManifestParser;
import org.osgi.framework.*;
import org.osgi.framework.Constants;
import org.osgi.framework.wiring.*;
import org.phidias.compile.BundleJavaManager;

import aQute.bnd.osgi.*;
import aQute.bnd.osgi.Clazz.QUERY;
import generic.io.NullPrintWriter;
import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.util.Msg;
import util.CollectionUtils;
import utilities.util.FileUtilities;

/**
 * Represents a Java source directory that is compiled on build to an OSGi bundle.
 * 
 * <p>A manifest and {@link BundleActivator} are generated if not already present.
 */
public class GhidraSourceBundle extends GhidraBundle {
	private static final String INSTRCTION_ACTIVATOR = "org.osgi.framework.BundleActivator";
	private static final String GENERATED_ACTIVATOR_CLASSNAME = "GeneratedActivator";
	private static final String GENERATED_VERSION = "1.0";

	/*
	 * Match the leftover part of a class file on removing the class name, e.g.
	 * we've found "MyClass.java", so we match "MyClass.class" by removing "MyClass" then
	 * computing IS_CLASS_FILE.test(".class") == true.  We  want to match inner 
	 * class files like "MyClass$2.class" too, so IS_CLASS_FILE.test("$2.class") is also true.
	 */
	private static final Predicate<String> IS_CLASS_FILE =
		Pattern.compile("(\\$.*)?\\.class", Pattern.CASE_INSENSITIVE).asMatchPredicate();

	/**
	 * Used to report source and class file deviation
	 */
	protected interface DiscrepancyCallback {
		/**
		 * Invoked when there is a discrepancy between {@code sourceFile} and its corresponding 
		 * class file(s), {@code classFiles}
		 * 
		 * @param sourceFile the source file or null to indicate the class files have no 
		 * corresponding source
		 * @param classFiles corresponding class file(s)
		 * @throws Throwable an exception
		 */
		void found(ResourceFile sourceFile, Collection<Path> classFiles) throws Throwable;
	}

	// This is a hash; it is used to create a unique directory name for this bundle
	private final String symbolicName;
	private final Path binaryDir;

	/**
	 *  The bundle location id
	 *  @see #getLocationIdentifier()
	 */
	private final String bundleLocationId;

	// These 2 lists are updated to track source file to class file changes; newSources are those
	// that need to be compiled; oldBinaries are those that no longer have source files (such as
	// when a source file is deleted)
	private final List<ResourceFile> newSources = new ArrayList<>();
	private final List<Path> oldBinaries = new ArrayList<>();

	private JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();

	// information indexed by source file
	private final Map<ResourceFile, BuildError> buildErrors = new HashMap<>();
	private final Map<ResourceFile, List<BundleRequirement>> sourceFileToRequirements =
		new HashMap<>();

	private final Map<String, List<ResourceFile>> requirementToSourceFileMap = new HashMap<>();
	private final Set<String> missedRequirements = new HashSet<>();
	private final Set<String> importPackageValues = new HashSet<>();

	/**
	 * Create a new GhidraSourceBundle.
	 * 
	 * @param bundleHost the instance this bundle will belong to
	 * @param sourceDirectory the source bundle directory
	 * @param enabled true to start enabled
	 * @param systemBundle true if this is a Ghidra system bundle
	 */
	public GhidraSourceBundle(BundleHost bundleHost, ResourceFile sourceDirectory, boolean enabled,
			boolean systemBundle) {
		super(bundleHost, sourceDirectory, enabled, systemBundle);

		this.symbolicName = sourceDirHash(getSourceDirectory());
		this.binaryDir = getCompiledBundlesDir().resolve(symbolicName);
		this.bundleLocationId =
			"reference:file://" + binaryDir.toAbsolutePath().normalize().toString();
	}

	/**
	 * (alias of {@link #getFile} for readability)
	 * @return the source directory this bundle represents
	 */
	private final ResourceFile getSourceDirectory() {
		return bundleFile;
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
	 * When a source bundle doesn't have a manifest, Ghidra computes the bundle's symbolic name as 
	 * a hash of the source directory path.
	 * 
	 * <p>This hash is also used as the final path component of the compile destination:
	 * <br/>&nbsp;{@code $USERHOME/.ghidra/.ghidra_<ghidra version>/osgi/compiled-bundles/<sourceDirHash> }
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
	 * Return the class name corresponding to a script in this source bundle.
	 * 
	 * @param sourceFile a source file from this bundle
	 * @return the class name
	 * @throws ClassNotFoundException if {@code sourceFile} isn't contained in this bundle
	 */
	public String classNameForScript(ResourceFile sourceFile) throws ClassNotFoundException {
		String relativePath = FileUtilities.relativizePath(getSourceDirectory(), sourceFile);
		if (relativePath == null) {
			throw new ClassNotFoundException(
				String.format("Failed to find script file '%s' in source directory '%s'",
					sourceFile, getSourceDirectory()));
		}
		// chop ".java" from the end
		relativePath = relativePath.substring(0, relativePath.length() - 5);
		return relativePath.replace(File.separatorChar, '.');
	}

	private void clearBuildErrors(ResourceFile sourceFile) {
		buildErrors.remove(sourceFile);
	}

	/**
	 * Append the given build error. 
	 * @param sourceFile the file w/ errors 
	 * @param err an error string
	 */
	private void buildError(ResourceFile sourceFile, String err) {
		BuildError error = buildErrors.computeIfAbsent(sourceFile, BuildError::new);
		error.append(err);
	}

	/**
	 * Get any errors associated with building the given source file.
	 * 
	 * @param sourceFile the source file
	 * @return the build error or null if no errors
	 */
	public BuildError getErrors(ResourceFile sourceFile) {
		return buildErrors.get(sourceFile);
	}

	/**
	 * Get the mapping from source file to BuildError.
	 * 
	 * @return the error file map
	 */
	public Map<ResourceFile, BuildError> getAllErrors() {
		return Collections.unmodifiableMap(buildErrors);
	}

	private String getPreviousBuildErrors() {
		return buildErrors.values()
				.stream()
				.map(BuildError::getMessage)
				.collect(Collectors.joining());
	}

	private String parseImportPackageMetadata(ResourceFile javaSource) {
		return GhidraScriptUtil.newScriptInfo(javaSource).getImportPackage();
	}

	/**
	 * Update build requirements based on {@code @importpackage} tag in java files in the 
	 * default (unnamed) package.
	 * 
	 * @throws GhidraBundleException on failure to parse the {@code @importpackage} tag
	 */
	private void updateRequirementsFromMetadata() throws GhidraBundleException {
		sourceFileToRequirements.clear();
		requirementToSourceFileMap.clear();
		importPackageValues.clear();

		for (ResourceFile rootSourceFile : getSourceDirectory().listFiles()) {
			if (!rootSourceFile.getName().endsWith(".java")) {
				continue;
			}

			// Without GhidraScriptComponentProvider.updateAvailableScriptFilesForDirectory, or 
			// GhidraScriptComponentProvider.newScript this might be the earliest need for
			// ScriptInfo, so allow construction.

			// NB: ScriptInfo will update field values if lastModified has changed since last time 
			// they were computed
			String importPackage = parseImportPackageMetadata(rootSourceFile);
			if (importPackage == null || importPackage.isEmpty()) {
				continue;
			}

			List<String> parts = ManifestParser.parseDelimitedString(importPackage.strip(), ",");
			importPackageValues.addAll(parts);
			List<BundleRequirement> requirements;
			try {
				requirements = OSGiUtils.parseImportPackage(importPackage);
			}
			catch (BundleException e) {
				throw new GhidraBundleException(getLocationIdentifier(),
					"@importpackage error", e);
			}
			sourceFileToRequirements.put(rootSourceFile, requirements);
			for (BundleRequirement requirement : requirements) {
				requirementToSourceFileMap
						.computeIfAbsent(requirement.toString(), x -> new ArrayList<>())
						.add(rootSourceFile);
			}
		}
	}

	/**
	 * Assumes that {@link #updateRequirementsFromMetadata()} has been called recently
	 * 
	 * @return deduped requirements
	 */
	private Map<String, BundleRequirement> getComputedReqs() {
		Map<String, BundleRequirement> dedupedReqs = new HashMap<>();
		sourceFileToRequirements.values()
				.stream()
				.flatMap(List::stream)
				.forEach(r -> dedupedReqs.putIfAbsent(r.toString(), r));

		return dedupedReqs;
	}

	private ManifestParser createSourceManifestParser() {
		ResourceFile manifestFile = getSourceManifestFile();
		if (!manifestFile.exists()) {
			return null;
		}

		try (InputStream is = manifestFile.getInputStream()) {
			Manifest manifest = new Manifest(is);
			Attributes mainAttributes = manifest.getMainAttributes();
			Map<String, Object> headerMap = mainAttributes.entrySet()
					.stream()
					.collect(Collectors.toMap(e -> e.getKey().toString(),
						e -> e.getValue().toString()));
			return new ManifestParser(null, null, null, headerMap);
		}
		catch (IOException | BundleException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public List<BundleRequirement> getAllRequirements() throws GhidraBundleException {
		ManifestParser parser = createSourceManifestParser();
		if (parser != null) {
			return parser.getRequirements();
		}

		updateRequirementsFromMetadata();
		Map<String, BundleRequirement> reqs = getComputedReqs();
		return new ArrayList<>(reqs.values());
	}

	private static void findPackageDirs(List<String> packages, ResourceFile dir) {
		boolean added = false;
		ResourceFile[] files = dir.listFiles(f -> f.isDirectory() || f.getName().endsWith(".java"));
		for (ResourceFile file : files) {
			if (!file.getName().matches("internal|private")) {
				if (file.isDirectory()) {
					findPackageDirs(packages, file);
				}
				else if (!added) {
					added = true;
					packages.add(dir.getAbsolutePath());
				}
			}
		}
	}

	@Override
	public List<BundleCapability> getAllCapabilities() throws GhidraBundleException {
		ManifestParser manifestParser = createSourceManifestParser();
		if (manifestParser != null) {
			return manifestParser.getCapabilities();
		}

		int sourceDirLength = getSourceDirectory().getAbsolutePath().length() + 1;
		List<String> packageDirs = new ArrayList<>();
		findPackageDirs(packageDirs, getSourceDirectory());
		StringBuilder sb = new StringBuilder();
		for (String packageDir : packageDirs) {
			// skip unnamed package
			if (packageDir.length() > sourceDirLength) {
				String packageName =
					packageDir.substring(sourceDirLength).replace(File.separatorChar, '.');
				sb.append(',');
				sb.append(packageName);
				sb.append(";version=\"" + GENERATED_VERSION + "\"");
			}
		}
		try {
			if (sb.length() == 0) {
				return Collections.emptyList();
			}
			return OSGiUtils.parseExportPackage(sb.substring(1));
		}
		catch (BundleException e) {
			throw new GhidraBundleException(getLocationIdentifier(), "Exports error", e);
		}
	}

	/**
	 * Look for new sources, metadata, manifest file.  This will find files that need to be 
	 * compiled and files that need to be removed.
	 * 
	 * <p>If files had errors last time, haven't changed, and no new requirements are available, 
	 * remove them.
	 * 
	 * @param writer for reporting status to user
	 * @throws IOException while accessing manifest file
	 * @throws OSGiException while parsing imports
	 */
	private void updateFromFilesystem(PrintWriter writer) throws IOException, OSGiException {

		newSources.clear();
		oldBinaries.clear();

		visitDiscrepancies((sourceFile, classFiles) -> {
			// sourceFile is either newer than its corresponding class files,
			// or there are no corresponding class files (meaning it's new),
			// or sourceFile=null and classFiles had no corresponding source
			if (sourceFile != null) {
				// these will be (re)compiled
				newSources.add(sourceFile);
			}
			if (classFiles != null) {
				// these will be deleted
				oldBinaries.addAll(classFiles);
			}
		});

		// we don't want to rebuild source files that had errors last time and haven't changed, so 
		// remove them from newSources.  Also remove old error messages.
		Iterator<ResourceFile> it = newSources.iterator();
		while (it.hasNext()) {
			ResourceFile newSourceFile = it.next();
			if (stillHasErrors(newSourceFile)) {
				it.remove();
			}
			else {
				// any errors are old, so remove them 
				buildErrors.remove(newSourceFile);
			}
		}
	}

	private boolean stillHasErrors(ResourceFile newSourceFile) {
		BuildError error = buildErrors.get(newSourceFile);
		if (error != null) {
			if (error.getLastModified() == newSourceFile.lastModified()) {
				return true;
			}
		}
		return false;
	}

	private void deleteOldBinaries() throws IOException {
		// dedup and omit files that don't exist
		oldBinaries.sort(null);

		Iterator<Path> toDelete =
			oldBinaries.stream().distinct().filter(Files::exists).sorted().iterator();
		for (Path path : CollectionUtils.asIterable(toDelete)) {
			Files.delete(path);
		}

		oldBinaries.clear();
	}

	private int getBuildErrorCount() {
		return buildErrors.size();
	}

	private int getNewSourcesCount() {
		return newSources.size();
	}

	/**
	 * Used just after {@link #build} to get the newly compiled source files.
	 * @return new source files
	 */
	public List<ResourceFile> getNewSources() {
		return Collections.unmodifiableList(newSources);
	}

	@Override
	public String getLocationIdentifier() {
		return bundleLocationId;
	}

	private ResourceFile getSourceManifestFile() {
		return new ResourceFile(getSourceDirectory(), "META-INF" + File.separator + "MANIFEST.MF");
	}

	private Path getBinaryManifestPath() {
		return binaryDir.resolve("META-INF").resolve("MANIFEST.MF");
	}

	private boolean hasSourceManifest() {
		return getSourceManifestFile().exists();
	}

	private boolean hasNewManifest() {
		ResourceFile sourceManifest = getSourceManifestFile();
		Path binaryManifest = getBinaryManifestPath();

		boolean oldOrMissingBinaryManifest = Files.notExists(binaryManifest) ||
			sourceManifest.lastModified() > binaryManifest.toFile().lastModified();
		return sourceManifest.exists() && oldOrMissingBinaryManifest;
	}

	private static boolean wipeContents(Path path) throws IOException {
		if (Files.exists(path)) {
			boolean anythingDeleted = false;
			try (Stream<Path> walk = Files.walk(path)) {
				for (Path p : (Iterable<Path>) walk.sorted(Comparator.reverseOrder())::iterator) {
					anythingDeleted |= Files.deleteIfExists(p);
				}
			}
			return anythingDeleted;
		}
		return false;
	}

	private boolean wipeBinDir() throws IOException {
		return wipeContents(binaryDir);
	}

	/**
	 * If source with a previous requirement error now resolves, add it to newSources.
	 *
	 * <p>The reason for the previous build error isn't necessarily a missing requirement, but this 
	 * shouldn't be too expensive.
	 */
	private void addSourcesThatNoLongerHaveMissingRequirements() {
		for (ResourceFile sourceFile : buildErrors.keySet()) {
			List<BundleRequirement> requirements = sourceFileToRequirements.get(sourceFile);
			if (requirements != null && !requirements.isEmpty() &&
				bundleHost.canResolveAll(requirements)) {
				if (!newSources.contains(sourceFile)) {
					newSources.add(sourceFile);
				}
				for (ResourceFile oldbin : correspondingBinaries(sourceFile)) {
					oldbin.delete();
				}
			}
		}
	}

	/**
	 * If a file that previously built without errors is now missing some requirements, rebuild it 
	 * to capture errors (if any). 
	 */
	private void addSourcesThatNowHaveMissingRequirements() {
		// if previous successes no longer resolve, (cleanup) and try again
		for (Entry<ResourceFile, List<BundleRequirement>> e : sourceFileToRequirements.entrySet()) {
			ResourceFile sourceFile = e.getKey();
			List<BundleRequirement> requirements = e.getValue();
			if (requirements != null && !requirements.isEmpty() &&
				!buildErrors.containsKey(sourceFile) && !bundleHost.canResolveAll(requirements)) {
				if (!newSources.contains(sourceFile)) {
					newSources.add(sourceFile);
				}

				Arrays.stream(correspondingBinaries(sourceFile))
						.map(rf -> rf.getFile(false).toPath())
						.forEach(oldBinaries::add);
			}
		}
	}

	@Override
	public boolean build(PrintWriter writer) throws Exception {

		writer = NullPrintWriter.dummyIfNull(writer);
		boolean needsCompile = false;

		if (hasSourceManifest()) {
			sourceFileToRequirements.clear();
			requirementToSourceFileMap.clear();
			List<BundleRequirement> reqs = new ArrayList<>(getAllRequirements());
			bundleHost.resolve(reqs);
			Set<String> newMissedRequirements = new HashSet<>();
			for (BundleRequirement req : reqs) {
				newMissedRequirements.add(req.toString());
			}
			if (hasNewManifest() || !newMissedRequirements.equals(missedRequirements)) {
				missedRequirements.clear();
				missedRequirements.addAll(newMissedRequirements);
				wipeBinDir();
				buildErrors.clear();
			}
			updateFromFilesystem(writer);
		}
		else {

			// this gets all source files from the file system that we know need to be compiled 
			// based upon missing or outdated class files
			updateFromFilesystem(writer);
			updateRequirementsFromMetadata();

			// these 2 calls handle source files that need to be compiled based upon changes in 
			// added or removed bundles / requirements
			addSourcesThatNoLongerHaveMissingRequirements();
			addSourcesThatNowHaveMissingRequirements();
		}

		int buildErrorsLastTime = getBuildErrorCount();
		int newSourceCount = getNewSourcesCount();
		if (newSourceCount == 0) {
			if (buildErrorsLastTime > 0) {
				writer.printf("%s hasn't changed, with %d file%s failing in previous build(s):\n",
					getSourceDirectory().toString(), buildErrorsLastTime,
					buildErrorsLastTime > 1 ? "s" : "");
				writer.printf("%s\n", getPreviousBuildErrors());
				writer.flush();
			}
		}
		else {
			needsCompile = true;
		}

		// finally, we should be able to handle empty directories
		if (!binaryDir.toFile().exists()) {
			needsCompile = true;
		}

		if (needsCompile) {
			// if there is a bundle at our locations, uninstall it
			Bundle osgiBundle = bundleHost.getOSGiBundle(getLocationIdentifier());
			if (osgiBundle != null) {
				bundleHost.deactivateSynchronously(osgiBundle);
			}

			// once we've committed to recompile and regenerate classes, delete the old stuff
			deleteOldBinaries();

			String summary = compileToExplodedBundle(writer);
			bundleHost.notifyBundleBuilt(this, summary);
			return true;
		}
		bundleHost.notifyBundleBuilt(this, null);
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
			Bundle bundle = getOSGiBundle();
			if (bundle != null) {
				bundleHost.deactivateSynchronously(bundle);
			}
			return anythingChanged || wipeBinDir();
		}
		catch (IOException | GhidraBundleException e) {
			Msg.showError(this, null, "Source bundle clean error",
				"While attempting to delete the compiled directory, an exception was thrown", e);
		}
		return anythingChanged;
	}

	private ResourceFile[] correspondingBinaries(ResourceFile source) {
		String parentPath = source.getParentFile().getAbsolutePath();
		int sourceDirLength = getSourceDirectory().getAbsolutePath().length();
		String relativePath = parentPath.substring(sourceDirLength);
		if (relativePath.startsWith(File.separator)) {
			relativePath = relativePath.substring(1);
		}

		String javaFileName = source.getName();
		String className = javaFileName.substring(0, javaFileName.length() - 5); // drop ".java"
		ResourceFile binarySubdir = new ResourceFile(binaryDir.resolve(relativePath).toFile());
		if (!binarySubdir.exists() || !binarySubdir.isDirectory()) {
			return new ResourceFile[] {};
		}

		return binarySubdir.listFiles(f -> {
			String fileName = f.getName();
			return fileName.startsWith(className) &&
				IS_CLASS_FILE.test(fileName.substring(className.length()));
		});
	}

	/**
	 * visit discrepancies between java source and corresponding class files.
	 * 
	 * <pre>
	 * walk resources to find:
	 *  - source files that are newer than their corresponding binary
	 *		reports (source file, list of corresponding binaries)
	 * 	- source files with no corresponding binary
	 *		reports (source file, empty list)
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
	 * @param discrepancy the discrepancy callback
	 */
	protected void visitDiscrepancies(DiscrepancyCallback discrepancy) {
		try {

			Deque<ResourceFile> stack = new ArrayDeque<>();
			ResourceFile sourceDir = getSourceDirectory();
			stack.add(sourceDir); // start in the source directory root
			while (!stack.isEmpty()) {
				ResourceFile sourceSubdir = stack.pop();
				String relPath = sourceSubdir.getAbsolutePath()
						.substring(sourceDir.getAbsolutePath().length());
				if (relPath.startsWith(File.separator)) {
					relPath = relPath.substring(1);
				}

				Path binarySubdir = binaryDir.resolve(relPath);
				ClassMapper mapper = new ClassMapper(binarySubdir);

				// for each source file, lookup class files by class name 
				for (ResourceFile sourceFile : sourceSubdir.listFiles()) {
					if (sourceFile.isDirectory()) {
						stack.push(sourceFile);
					}
					else {
						List<Path> classFiles = mapper.findAndRemove(sourceFile);
						if (classFiles != null) {
							discrepancy.found(sourceFile, classFiles);
						}
					}
				}
				// any remaining .class files are missing .java files
				if (mapper.hasExtraClassFiles()) {
					discrepancy.found(null, mapper.extraClassFiles());
				}
			}
		}
		catch (Throwable e) {
			Msg.error(this, "Exception while searching for file system discrepancies ", e);
		}
	}

	/* 
	 * Requirements that resolve internally are never "missing", but resolve _after_ build/install
	 */
	private boolean resolveInternally(List<BundleRequirement> requirements)
			throws GhidraBundleException {
		if (requirements.isEmpty()) {
			return true;
		}

		List<BundleCapability> capabilities = getAllCapabilities();
		Iterator<BundleRequirement> requirementIterator = requirements.iterator();
		boolean anyMissing = false;
		while (requirementIterator.hasNext()) {
			BundleRequirement requirement = requirementIterator.next();
			if (capabilities.stream().anyMatch(requirement::matches)) {
				requirementIterator.remove();
			}
			else {
				anyMissing = true;
			}
		}
		return !anyMissing;
	}

	/*
	 * When calling the java compiler programmatically, we map import requests to files with a 
	 * custom {@link JavaFileManager}.  We wrap the system JavaFileManager with one that handles 
	 * ResourceFiles then wrap that with phidias, which handles imports based on bundle 
	 * requirements.
	 */
	private BundleJavaManager createBundleJavaManager(PrintWriter writer, Summary summary,
			List<String> options) throws IOException, GhidraBundleException {

		ResourceFileJavaFileManager resourceFileJavaManager = new ResourceFileJavaFileManager(
			Collections.singletonList(getSourceDirectory()), buildErrors.keySet());
		BundleJavaManager bundleJavaManager = new MyBundleJavaManager(bundleHost.getHostFramework(),
			resourceFileJavaManager, options);

		// The phidias BundleJavaManager is for compiling from within a bundle -- it makes the
		// bundle dependencies available to the compiler classpath.  Here, we are compiling in an 
		// as-yet non-existing bundle, so we forge the wiring based on @importpackage metadata.

		// get wires for currently active bundles to satisfy all requirements
		List<BundleRequirement> requirements = getAllRequirements();
		List<BundleWiring> bundleWirings = bundleHost.resolve(requirements);
		if (!resolveInternally(requirements)) {
			writeErrorUnresolved(writer, summary, requirements);
		}

		// send the capabilities to phidias
		bundleWirings.forEach(bundleJavaManager::addBundleWiring);
		return bundleJavaManager;
	}

	private void writeErrorUnresolved(PrintWriter writer, Summary summary,
			List<BundleRequirement> requirements) {

		writer.printf("%d import requirement%s remain%s unresolved:\n", requirements.size(),
			requirements.size() > 1 ? "s" : "", requirements.size() > 1 ? "" : "s");
		for (BundleRequirement requirement : requirements) {
			List<ResourceFile> requiringFiles =
				requirementToSourceFileMap.get(requirement.toString());
			if (requiringFiles != null && requiringFiles.size() > 0) {
				writer.printf("  %s, from %s\n", requirement.toString(),
					requiringFiles.stream()
							.map(generic.util.Path::toPathString)
							.collect(Collectors.joining(",")));

				for (ResourceFile sourceFile : requiringFiles) {
					buildError(sourceFile,
						generic.util.Path.toPathString(sourceFile) + " : failed import " +
							OSGiUtils.extractPackageNamesFromFailedResolution(
								requirement.toString()));
				}
			}
			else {
				writer.printf("  %s\n", requirement.toString());
			}
		}

		String singularity = requirements.size() > 1 ? "s" : "";
		String missing = requirements.stream()
				.flatMap(
					r -> OSGiUtils.extractPackageNamesFromFailedResolution(r.toString()).stream())
				.distinct()
				.collect(Collectors.joining(","));
		summary.printf("%d missing package import%s:%s", requirements.size(), singularity, missing);
	}

	/*
	 * Try building source files. On success return true.
	 * 
	 * If build fails, collect errors, remove files that caused 
	 * errors from source files, and return false.
	 */
	private boolean tryBuild(PrintWriter writer, BundleJavaManager bundleJavaManager,
			List<ResourceFileJavaFileObject> sourceFiles, List<String> options) throws IOException {
		DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
		JavaCompiler.CompilationTask task =
			compiler.getTask(writer, bundleJavaManager, diagnostics, options, null, sourceFiles);

		Boolean successfulCompilation = task.call();
		if (successfulCompilation) {
			return true;
		}

		Set<ResourceFileJavaFileObject> filesWithErrors = new HashSet<>();
		for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
			String error = diagnostic.toString() + "\n";
			writer.write(error);
			ResourceFileJavaFileObject sourceFileObject =
				(ResourceFileJavaFileObject) diagnostic.getSource();
			ResourceFile sourceFile = sourceFileObject.getFile();
			buildError(sourceFile, error); // remember all errors for this file
			filesWithErrors.add(sourceFileObject);
		}
		for (ResourceFileJavaFileObject sourceFileObject : filesWithErrors) {
			if (sourceFiles.remove(sourceFileObject)) {
				writer.printf("skipping %s\n", sourceFileObject.getFile().toString());
			}
			else {
				// we can't tolerate infinite loops here, so bail
				throw new IOException("compilation error loop condition for " +
					sourceFileObject.getFile().toString());
			}
		}
		return false;
	}

	/**
	 * Generate a manifest (and an activator)
	 * 
	 * <p>Assumes that {@link #updateRequirementsFromMetadata()} has been called recently
	 */
	private String generateManifest(PrintWriter writer, Summary summary, Path binaryManifest)
			throws OSGiException, IOException {
		// no manifest, so create one with bndtools
		Analyzer analyzer = new Analyzer();
		analyzer.setJar(new Jar(binaryDir.toFile())); // give bnd the contents
		analyzer.setProperty("Bundle-SymbolicName",
			GhidraSourceBundle.sourceDirHash(getSourceDirectory()));
		analyzer.setProperty("Bundle-Version", GENERATED_VERSION);

		if (importPackageValues.isEmpty()) {
			analyzer.setProperty("Import-Package", "*");
		}
		else {
			// constrain analyzed imports according to what's declared in @importpackage tags
			analyzer.setProperty("Import-Package",
				importPackageValues.stream().collect(Collectors.joining(",")) + ",*");
		}

		analyzer.setProperty("Export-Package", "!*.private.*,!*.internal.*,*");

		try {
			Manifest manifest;
			try {
				manifest = analyzer.calcManifest();
			}
			catch (Exception e) {
				summary.print("Bad manifest");
				throw new OSGiException("Failed to calculate manifest by analyzing code", e);
			}

			if (!addActivatorClass(writer, analyzer, manifest, summary)) {
				return summary.getValue();
			}

			// write the manifest
			Files.createDirectories(binaryManifest.getParent());
			try (OutputStream out = Files.newOutputStream(binaryManifest)) {
				manifest.write(out);
			}
		}
		finally {
			analyzer.close();
		}
		return summary.getValue();
	}

	private boolean addActivatorClass(PrintWriter writer, Analyzer analyzer, Manifest manifest,
			Summary summary) throws OSGiException, IOException {

		String activatorClassName = null;
		try {
			for (Clazz clazz : analyzer.getClassspace().values()) {
				if (clazz.is(QUERY.IMPLEMENTS,
					new Instruction(INSTRCTION_ACTIVATOR), analyzer)) {
					Msg.trace(this, "Found BundleActivator class " + clazz);
					activatorClassName = clazz.toString();
				}
			}
		}
		catch (Exception e) {
			summary.print("Failed bnd analysis");
			throw new OSGiException("Failed to query classes while searching for activator", e);
		}

		Attributes manifestAttributes = manifest.getMainAttributes();
		if (activatorClassName != null) {
			manifestAttributes.putValue(Constants.BUNDLE_ACTIVATOR, activatorClassName);
			return true;
		}

		activatorClassName = GENERATED_ACTIVATOR_CLASSNAME;
		if (!buildDefaultActivator(binaryDir, activatorClassName, writer)) {
			summary.print("Failed to build generated activator");
			return false;
		}

		// since we add the activator after bndtools built the imports, add its imports too
		String imports = manifestAttributes.getValue(Constants.IMPORT_PACKAGE);
		String activatorPackageName = GhidraBundleActivator.class.getPackageName();
		if (imports == null) {
			manifestAttributes.putValue(Constants.IMPORT_PACKAGE, activatorPackageName);
		}
		else {
			manifestAttributes.putValue(Constants.IMPORT_PACKAGE, imports + "," +
				activatorPackageName);
		}
		manifestAttributes.putValue(Constants.BUNDLE_ACTIVATOR, activatorClassName);
		return true;
	}

	/**
	 * create and compile a default bundle activator
	 * 
	 * @param bindir destination for class file
	 * @param activatorClassName the name to use for the generated activator class
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

		try (StandardJavaFileManager javaFileManager =
			compiler.getStandardFileManager(null, null, null);
				BundleJavaManager bundleManager = new MyBundleJavaManager(
					bundleHost.getHostFramework(), javaFileManager, options);) {
			Iterable<? extends JavaFileObject> sourceFiles =
				javaFileManager.getJavaFileObjectsFromPaths(List.of(activatorSourceFileName));
			DiagnosticCollector<JavaFileObject> diagnostics =
				new DiagnosticCollector<>();
			JavaCompiler.CompilationTask task = compiler.getTask(writer, bundleManager,
				diagnostics, options, null, sourceFiles);
			if (task.call()) {
				return true;
			}

			for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics
					.getDiagnostics()) {
				writer.write(diagnostic.getSource().toString() + ": " +
					diagnostic.getMessage(null) + "\n");
			}
			return false;
		}
	}

	/**
	 * Compile a source directory to an exploded bundle.
	 *  
	 * @param writer for updating the user during compilation
	 * @return a summary of the work performed
	 * @throws IOException for source/manifest file reading/generation and binary deletion/creation
	 * @throws OSGiException if generation of bundle metadata fails
	 */
	private String compileToExplodedBundle(PrintWriter writer) throws IOException, OSGiException {

		Files.createDirectories(binaryDir);

		Summary summary = new Summary();

		List<String> options = new ArrayList<>();
		options.add("-g");
		options.add("-d");
		options.add(binaryDir.toString());
		options.add("-sourcepath");
		options.add(getSourceDirectory().toString());
		options.add("-classpath");
		options.add(
			System.getProperty("java.class.path") + File.pathSeparator + binaryDir.toString());
		options.add("-proc:none");

		// clear build errors
		for (ResourceFile sourceFile : newSources) {
			clearBuildErrors(sourceFile);
		}

		try (BundleJavaManager bundleJavaManager =
			createBundleJavaManager(writer, summary, options)) {

			final List<ResourceFileJavaFileObject> sourceFiles = newSources.stream()
					.map(sf -> new ResourceFileJavaFileObject(sf.getParentFile(), sf, Kind.SOURCE))
					.collect(Collectors.toList());

			Path binaryManifest = getBinaryManifestPath();
			if (Files.exists(binaryManifest)) {
				Files.delete(binaryManifest);
			}

			// try to compile, if we fail, avoid offenders and try again
			while (!sourceFiles.isEmpty()) {
				if (tryBuild(writer, bundleJavaManager, sourceFiles, options)) {
					break;
				}
			}

			// buildErrors is now up to date, set status
			if (getBuildErrorCount() > 0) {
				int count = getBuildErrorCount();
				summary.printf("%d source file%s with errors", count, count > 1 ? "s" : "");
			}

			ResourceFile sourceManifest = getSourceManifestFile();
			if (sourceManifest.exists()) {
				Files.createDirectories(binaryManifest.getParent());
				try (InputStream inStream = sourceManifest.getInputStream()) {
					Files.copy(inStream, binaryManifest, StandardCopyOption.REPLACE_EXISTING);
				}
				return summary.getValue();
			}

			return generateManifest(writer, summary, binaryManifest);
		}
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	private static class MyBundleJavaManager extends BundleJavaManager {
		private static URL[] EMPTY_URL_ARRAY = new URL[0];

		MyBundleJavaManager(Bundle bundle, JavaFileManager javaFileManager, List<String> options)
				throws IOException {
			super(bundle, javaFileManager, options);
		}

		/**
		 * Since the JavaCompiler tasks can close the class loader returned by this method, make 
		 * sure we're returning a copy.
		 */
		@Override
		public ClassLoader getClassLoader() {
			return new URLClassLoader(EMPTY_URL_ARRAY, super.getClassLoader());
		}
	}

	private static class Summary {
		private static final String SEPERATOR = ", ";
		private final StringWriter stringWriter = new StringWriter();
		private final PrintWriter printWriter = new PrintWriter(stringWriter, true);

		void printf(String format, Object... args) {
			if (stringWriter.getBuffer().length() > 0) {
				printWriter.write(SEPERATOR);
			}
			printWriter.printf(format, args);
		}

		void print(String arg) {
			printWriter.print(arg);
		}

		String getValue() {
			printWriter.flush();
			return stringWriter.getBuffer().toString();
		}
	}

	/**
	 * Index *.class files in a directory by class name, e.g.
	 * 
	 * <pre>
	 *    "A" -> [directory/A.class]
	 *    "B" -> [directory/B.class, directory/B$inner.class]
	 * </pre>
	 * 
	 * <p>A list of classes are then processed with {@link ClassMapper#findAndRemove}.
	 * 
	 * <p>After processing, "extras" are handled with {@link ClassMapper#extraClassFiles}.
	 */
	private static class ClassMapper {
		private final Map<String, List<Path>> classToClassFilesMap;

		/**
		 * Map classes in {@code directory} with {@link ClassMapper}.
		 *  
		 * @param directory the directory
		 * @throws IOException if there's a problem listing files
		 */
		ClassMapper(Path directory) throws IOException {
			if (!Files.exists(directory)) {
				classToClassFilesMap = Collections.emptyMap();
				return;
			}

			try (Stream<Path> paths = Files.list(directory)) {
				classToClassFilesMap = paths.filter(p -> Files.isRegularFile(p))
						.filter(p -> p.getFileName().toString().endsWith(".class"))
						.collect(groupingBy(this::getClassName));
			}
		}

		private String getClassName(Path p) {
			String fileName = p.getFileName().toString();
			// if f is the class file of an inner class, use the class name
			int money = fileName.indexOf('$');
			if (money >= 0) {
				return fileName.substring(0, money);
			}
			return fileName.substring(0, fileName.length() - 6); // drop ".class"
		}

		List<Path> findAndRemove(ResourceFile sourceFile) {
			String className = sourceFile.getName();
			if (!className.endsWith(".java")) {
				return null;
			}

			className = className.substring(0, className.length() - 5); // drop ".java"
			long lastModifiedSource = sourceFile.lastModified();
			List<Path> classFiles = classToClassFilesMap.remove(className);
			if (classFiles == null) {
				classFiles = Collections.emptyList();
			}

			long lastModifiedClassFile = classFiles.isEmpty() ? -1
					: classFiles.stream()
							.mapToLong(p -> p.toFile().lastModified())
							.min()
							.getAsLong();
			// if source is newer than the oldest binary, report
			if (lastModifiedSource > lastModifiedClassFile) {
				return classFiles;
			}
			return null;
		}

		boolean hasExtraClassFiles() {
			return !classToClassFilesMap.isEmpty();
		}

		Collection<Path> extraClassFiles() {
			return classToClassFilesMap.values()
					.stream()
					.flatMap(l -> l.stream())
					.collect(Collectors.toList());
		}
	}
}
