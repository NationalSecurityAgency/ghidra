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
import java.util.stream.Stream;

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
import ghidra.app.plugin.core.osgi.BundleHost.BuildFailure;
import ghidra.app.script.*;
import ghidra.util.Msg;

/**
 * The SourceBundleInfo class is a cache of information for bundles built from source directories.
 */
public class GhidraSourceBundle extends GhidraBundle {
	public interface DiscrepencyCallback {
		void found(ResourceFile source_file, Collection<Path> class_files) throws Throwable;
	}

	final private String symbolicName;
	final private Path binDir;
	final private String bundleLoc;

	final List<ResourceFile> newSources = new ArrayList<>();
	final List<Path> oldBin = new ArrayList<>();

	static final String GENERATED_ACTIVATOR_CLASSNAME = "GeneratedActivator";
	private JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();

	//// information indexed by source file

	final HashMap<ResourceFile, BuildFailure> buildErrors = new HashMap<>();
	final HashMap<ResourceFile, List<BundleRequirement>> buildReqs = new HashMap<>();
	final HashMap<String, List<ResourceFile>> req2file = new HashMap<>();

	// cached values parsed form @imports tags on default-package source files

	public GhidraSourceBundle(BundleHost bundleHost, ResourceFile sourceDirectory, boolean enabled,
			boolean systemBundle) {
		super(bundleHost, sourceDirectory, enabled, systemBundle);

		this.symbolicName = BundleHost.getSymbolicNameFromSourceDir(path);
		this.binDir = BundleHost.getCompiledBundlesDir().resolve(symbolicName);

		this.bundleLoc = "reference:file://" + getBinDir().toAbsolutePath().normalize().toString();
	}

	/**
	 * for testing only!!!
	 * 
	 * @param sourceFile a ghidra script file
	 * @return the directory its class is compiled to
	 */
	static public Path getBindirFromScriptFile(ResourceFile sourceFile) {
		ResourceFile tmpSourceDir = sourceFile.getParentFile();
		String tmpSymbolicName = BundleHost.getSymbolicNameFromSourceDir(tmpSourceDir);
		return BundleHost.getCompiledBundlesDir().resolve(tmpSymbolicName);
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

	ResourceFile getSourceDir() {
		return path;
	}

	Path getBinDir() {
		return binDir;
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
		BuildFailure f =
			buildErrors.computeIfAbsent(sourceFile, x -> new BundleHost.BuildFailure());
		f.when = sourceFile.lastModified();
		f.message.append(err);
	}

	public BuildFailure getErrors(ResourceFile sourceFile) {
		return buildErrors.get(sourceFile);
	}

	private String getPreviousBuildErrors() {
		return buildErrors.values().stream().map(e -> e.message.toString()).collect(
			Collectors.joining());
	}

	/**
	 * update buildReqs based on \@imports tag in java files from the default package
	 * 
	 * @throws GhidraBundleException on failure to parse the \@imports tag
	 */
	private void updateRequirementsFromMetadata() throws GhidraBundleException {
		buildReqs.clear();
		req2file.clear();

		for (ResourceFile rf : path.listFiles()) {
			if (rf.getName().endsWith(".java")) {
				// without GhidraScriptComponentProvider.updateAvailableScriptFilesForDirectory, or GhidraScriptComponentProvider.newScript
				// this might be the earliest need for ScriptInfo, so allow construction.

				// NB: ScriptInfo will update field values if lastModified has changed since last time they were computed
				ScriptInfo si = GhidraScriptUtil.getScriptInfo(rf);
				String imps = si.getImports();
				if (imps != null && !imps.isEmpty()) {
					List<BundleRequirement> reqs;
					try {
						reqs = BundleHost.parseImports(imps);
					}
					catch (BundleException e) {
						throw new GhidraBundleException(getBundleLoc(), "parsing manifest", e);
					}
					buildReqs.put(rf, reqs);
					for (BundleRequirement req : reqs) {
						req2file.computeIfAbsent(req.toString(), x -> new ArrayList<>()).add(rf);
					}
				}
			}
		}
	}

	private List<BundleRequirement> getComputedReqs() {
		Map<String, BundleRequirement> dedupedReqs = new HashMap<>();
		buildReqs.values().stream().flatMap(List::stream).forEach(
			r -> dedupedReqs.putIfAbsent(r.toString(), r));

		return new ArrayList<>(dedupedReqs.values());
	}

	@Override
	public List<BundleRequirement> getAllReqs() {
		try {
			updateRequirementsFromMetadata();
		}
		catch (GhidraBundleException e) {
			throw new RuntimeException(e);
		}
		return getComputedReqs();
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
			BuildFailure f = buildErrors.get(sf);
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
		for (Path bf : oldBin) {
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

	public List<ResourceFile> getNewSources() {
		return newSources;
	}

	long lastCompileAttempt;

	void compileAttempted() {
		lastCompileAttempt = System.currentTimeMillis();
	}

	long getLastCompileAttempt() {
		return lastCompileAttempt;
	}

	String summary = "";

	void setSummary(String summary) {
		this.summary = summary;
	}

	void appendSummary(String s) {
		if (!summary.isEmpty()) {
			summary += ", " + s;
		}
		else {
			summary = s;
		}
	}

	@Override
	public String getSummary() {
		return summary;
	}

	@Override
	public String getBundleLoc() {
		return bundleLoc;
	}

	boolean hasNewManifest() throws IOException {
		ResourceFile smf =
			new ResourceFile(getSourceDir(), "META-INF" + File.separator + "MANIFEST.MF");
		Path dmf = getBinDir().resolve("META-INF").resolve("MANIFEST.MF");

		return smf.exists() && (Files.notExists(dmf) ||
			smf.lastModified() > Files.getLastModifiedTime(dmf).toMillis());
	}

	static protected boolean wipeContents(Path path) throws IOException {
		if (Files.exists(path)) {
			boolean anythingDeleted = false;
			for (Path p : (Iterable<Path>) Files.walk(path).sorted(
				Comparator.reverseOrder())::iterator) {
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
			List<BundleRequirement> reqs = buildReqs.get(sf);
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
		for (Entry<ResourceFile, List<BundleRequirement>> e : buildReqs.entrySet()) {
			ResourceFile sf = e.getKey();
			List<BundleRequirement> reqs = e.getValue();
			if (reqs != null && !reqs.isEmpty() && !buildErrors.containsKey(sf) &&
				!bundleHost.canResolveAll(reqs)) {
				if (!newSources.contains(sf)) {
					newSources.add(sf);
				}
				for (ResourceFile oldbin : correspondingBinaries(sf)) {
					oldbin.delete();
				}
			}
		}

		int failing = getFailingSourcesCount();
		int newSourcecount = getNewSourcesCount();

		long lastBundleActivation = 0; // XXX record last bundle activation in bundlehost
		if (failing > 0 && (lastBundleActivation > getLastCompileAttempt())) {
			needsCompile = true;
		}

		if (newSourcecount == 0) {
			if (failing > 0) {
				writer.printf("%s hasn't changed, with %d file%s failing in previous build(s):\n",
					getSourceDir().toString(), failing, failing > 1 ? "s" : "");
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
			// XXX update status?
			// writer.printf("%d new files, %d skipped, %s\n", newSourcecount, failing, newManifest ? ", new manifest" : "");

			// if there a bundle is currently active, uninstall it
			Bundle b = getBundle();
			if (b != null) {
				bundleHost.deactivateSynchronously(b);
			}

			// once we've committed to recompile and regenerate generated classes, delete the old stuff
			deleteOldBinaries();

			compileToExplodedBundle(writer);
			bundleHost.fireBundleBuilt(this);
			return true;
		}
		return false;
	}

	@Override
	public boolean clean() {
		try {
			Bundle b = getBundle();
			if (b != null) {
				bundleHost.deactivateSynchronously(b);
			}
			return wipeBinDir();
		}
		catch (IOException | GhidraBundleException | InterruptedException e) {
			Msg.showError(this, null, "source bundle clean error",
				"while attempting to delete the compiled directory, an exception was thrown", e);
		}
		return false;
	}

	private static Predicate<String> bintail =
		Pattern.compile("(\\$.*)?\\.class", Pattern.CASE_INSENSITIVE).asMatchPredicate();

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
			return nn.startsWith(n) && bintail.test(nn.substring(n.length()));
		});
	}

	/**
	 * walk the filesystem to find:
	 *  - source files that are newer than their corresponding binary
	 *		reports (source file, list of corresponding binaries)
	 * 	- source files with no corresponding binary
	 *		reports (source file, <empty list>)
	 *  - binary files with no corresponding source
	 *  	reports (null, list of binary files)
	 *  
	 *   for a source file <source_root>/com/blah/Blah.java
	 *   
	 *   all of the following binaries would correspond:
	 *   	<binary_root>/com/blah/Blah.class
	 *   	<binary_root>/com/blah/Blah$Inner.class
	 *   	<binary_root>/com/blah/Blah$12.class
	 *   	<binary_root>/com/blah/Blah$12.class
	 *   	<binary_root>/com/blah/Blah$Inner$Innerer.class
	 *   	...
	 * 
	 * @param cb callback
	 */
	private void visitDiscrepencies(DiscrepencyCallback cb) {
		try {
			// delete class files for which java is either newer, or no longer exists
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
							long source_modtime = sf.lastModified();
							List<Path> bfs = binfiles.remove(n.substring(0, n.length() - 5));
							long bin_modtime = (bfs == null || bfs.isEmpty()) ? -1
									: bfs.stream().mapToLong(
										bf -> bf.toFile().lastModified()).min().getAsLong();
							// if source is newer than the oldest binary, report
							if (source_modtime > bin_modtime) {
								cb.found(sf, bfs);
							}
						}
					}
				}
				// any remaining .class files are missing .java files
				if (!binfiles.isEmpty()) {
					cb.found(null, binfiles.values().stream().flatMap(l -> l.stream()).collect(
						Collectors.toList()));
				}
			}
		}
		catch (Throwable t) {
			t.printStackTrace();
		}
	}

	/**
	 *  compile a source directory to an exploded bundle
	 *  
	 * @param writer for updating the user during compilation
	 * @throws IOException for source/manifest file reading/generation and binary deletion/creation
	 * @throws OSGiException if generation of bundle metadata fails
	 */
	private void compileToExplodedBundle(PrintWriter writer) throws IOException, OSGiException {

		compileAttempted();
		ResourceFile srcdir = getSourceDir();
		Path bindir = getBinDir();
		Files.createDirectories(bindir);

		List<String> options = new ArrayList<>();
		options.add("-g");
		options.add("-d");
		options.add(bindir.toString());
		options.add("-sourcepath");
		options.add(srcdir.toString());
		options.add("-classpath");
		options.add(System.getProperty("java.class.path") + File.pathSeparator + bindir.toString());
		options.add("-proc:none");

		final ResourceFileJavaFileManager rfm = new ResourceFileJavaFileManager(
			Collections.singletonList(getSourceDir()), buildErrors.keySet());

		BundleJavaManager bjm = new BundleJavaManager(bundleHost.getHostFramework(), rfm, options);
		// The phidias BundleJavaManager is for compiling from within a bundle -- it makes the
		// bundle dependencies available to the compiler classpath.  Here, we are compiling in an as-yet 
		// non-existing bundle, so we forge the wiring based on @imports metadata.

		// XXX skip this if there's a source manifest, emit warnings about @imports
		// get wires for currently active bundles to satisfy all requirements
		List<BundleRequirement> reqs = getAllReqs();
		List<BundleWiring> bundleWirings = bundleHost.resolve(reqs);

		if (!reqs.isEmpty()) {
			writer.printf("%d import requirement%s remain%s unresolved:\n", reqs.size(),
				reqs.size() > 1 ? "s" : "", reqs.size() > 1 ? "" : "s");
			for (BundleRequirement req : reqs) {
				writer.printf("  %s\n", req.toString());
			}

			setSummary(
				String.format("%d missing @import%s:%s", reqs.size(), reqs.size() > 1 ? "s" : "",
					reqs.stream().flatMap(
						r -> OSGiUtils.extractPackages(r.toString()).stream()).distinct().collect(
							Collectors.joining(","))));
		}
		else {
			setSummary("");
		}
		// send the capabilities to phidias
		bundleWirings.forEach(bjm::addBundleWiring);

		final List<ResourceFileJavaFileObject> sourceFiles = newSources.stream().map(
			sf -> new ResourceFileJavaFileObject(sf.getParentFile(), sf, Kind.SOURCE)).collect(
				Collectors.toList());

		Path dmf = bindir.resolve("META-INF").resolve("MANIFEST.MF");
		if (Files.exists(dmf)) {
			Files.delete(dmf);
		}

		// try to compile, if we fail, avoid offenders and try again
		while (!sourceFiles.isEmpty()) {
			DiagnosticCollector<JavaFileObject> diagnostics =
				new DiagnosticCollector<JavaFileObject>();
			JavaCompiler.CompilationTask task =
				compiler.getTask(writer, bjm, diagnostics, options, null, sourceFiles);
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
					throw new IOException("compilation error loop condition for " + sf.getFile().toString());
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
			appendSummary(String.format("%d failing source files", getFailingSourcesCount()));
		}

		ResourceFile smf = new ResourceFile(srcdir, "META-INF" + File.separator + "MANIFEST.MF");
		if (smf.exists()) {
			System.err.printf("Found manifest, not generating one\n");
			Files.createFile(dmf);
			Files.copy(smf.getInputStream(), dmf, StandardCopyOption.REPLACE_EXISTING);
			return;
		}

		// no manifest, so create one with bndtools
		Analyzer analyzer = new Analyzer();
		analyzer.setJar(new Jar(bindir.toFile())); // give bnd the contents
		Stream<Object> bjars = Files.list(BundleHost.getCompiledBundlesDir()).filter(
			f -> f.toString().endsWith(".jar")).map(f -> {
				try {
					return new Jar(f.toFile());
				}
				catch (IOException e1) {
					e1.printStackTrace(writer);
					return null;
				}
			});

		analyzer.addClasspath(bjars.collect(Collectors.toUnmodifiableList()));
		analyzer.setProperty("Bundle-SymbolicName",
			BundleHost.getSymbolicNameFromSourceDir(srcdir));
		analyzer.setProperty("Bundle-Version", "1.0");
		// XXX we must constrain analyzed imports according to constraints declared in @imports tags
		analyzer.setProperty("Import-Package", "*");
		analyzer.setProperty("Export-Package", "!*.private.*,!*.internal.*,*");
		// analyzer.setBundleActivator(s);

		try {
			Manifest manifest;
			try {
				manifest = analyzer.calcManifest();
			}
			catch (Exception e) {
				appendSummary("bad manifest");
				throw new OSGiException("failed to calculate manifest by analyzing code", e);
			}
			Attributes ma = manifest.getMainAttributes();

			String activator_classname = null;
			try {
				for (Clazz clazz : analyzer.getClassspace().values()) {
					if (clazz.is(QUERY.IMPLEMENTS,
						new Instruction("org.osgi.framework.BundleActivator"), analyzer)) {
						System.err.printf("found BundleActivator class %s\n", clazz);
						activator_classname = clazz.toString();
					}
				}
			}
			catch (Exception e) {
				appendSummary("failed bnd analysis");
				throw new OSGiException("failed to query classes while searching for activator", e);
			}
			if (activator_classname == null) {
				activator_classname = GENERATED_ACTIVATOR_CLASSNAME;
				if (!buildDefaultActivator(bindir, activator_classname, writer)) {
					appendSummary("failed to build generated activator");
					return;
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
			ma.putValue(Constants.BUNDLE_ACTIVATOR, activator_classname);

			// write the manifest
			Files.createDirectories(dmf.getParent());
			try (OutputStream out = Files.newOutputStream(dmf)) {
				manifest.write(out);
			}
		}
		finally {
			analyzer.close();
		}
	}

	/**
	 * create and compile a default bundle activator
	 * 
	 * @param bindir destination for class file
	 * @param activator_classname the name to use for the genearted activator class
	 * @param writer for writing compile errors
	 * @return true if compilation succeeded
	 * @throws IOException for failed write of source/binary activator
	 */
	private boolean buildDefaultActivator(Path bindir, String activator_classname, Writer writer)
			throws IOException {
		Path activator_dest = bindir.resolve(activator_classname + ".java");

		try (PrintWriter out =
			new PrintWriter(Files.newBufferedWriter(activator_dest, Charset.forName("UTF-8")))) {
			out.println("import " + GhidraBundleActivator.class.getName() + ";");
			out.println("import org.osgi.framework.BundleActivator;");
			out.println("import org.osgi.framework.BundleContext;");
			out.println("public class " + GENERATED_ACTIVATOR_CLASSNAME +
				" extends GhidraBundleActivator {");
			out.println("  protected void start(BundleContext bc, Object api) {");
			out.println("    // TODO: stuff to do on bundle start");
			out.println("  }");
			out.println("  protected void stop(BundleContext bc, Object api) {");
			out.println("    // TODO: stuff to do on bundle stop");
			out.println("  }");
			out.println();
			out.println("}");
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

		StandardJavaFileManager fm = compiler.getStandardFileManager(null, null, null);
		BundleJavaManager bjm = new BundleJavaManager(bundleHost.getHostFramework(), fm, options);
		Iterable<? extends JavaFileObject> sourceFiles =
			fm.getJavaFileObjectsFromPaths(List.of(activator_dest));
		DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<JavaFileObject>();
		JavaCompiler.CompilationTask task =
			compiler.getTask(writer, bjm, diagnostics, options, null, sourceFiles);
		if (!task.call()) {
			for (Diagnostic<? extends JavaFileObject> d : diagnostics.getDiagnostics()) {
				writer.write(d.getSource().toString() + ": " + d.getMessage(null) + "\n");
			}
			return false;
		}
		return true;
	}

}
