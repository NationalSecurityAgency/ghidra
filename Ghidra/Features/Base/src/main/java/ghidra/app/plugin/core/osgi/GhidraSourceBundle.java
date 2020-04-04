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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleException;
import org.osgi.framework.wiring.BundleRequirement;

import generic.io.NullPrintWriter;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.BundleHost.BuildFailure;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.ScriptInfo;
import ghidra.util.Msg;

/**
 * The SourceBundleInfo class is a cache of information for bundles built from source directories.
 */
public class GhidraSourceBundle implements GhidraBundle {
	public interface DiscrepencyCallback {
		void found(ResourceFile source_file, Collection<Path> class_files) throws Throwable;
	}

	final private BundleHost bundleHost;
	final private ResourceFile sourceDir;

	final private String symbolicName;
	final private Path binDir;
	final private String bundleLoc;

	final List<ResourceFile> newSources = new ArrayList<>();
	final List<Path> oldBin = new ArrayList<>();

	//// information indexed by source file

	final HashMap<ResourceFile, BuildFailure> buildErrors = new HashMap<>();
	final HashMap<ResourceFile, List<BundleRequirement>> buildReqs = new HashMap<>();
	final HashMap<String, List<ResourceFile>> req2file = new HashMap<>();

	// cached values parsed form @imports tags on default-package source files

	public GhidraSourceBundle(BundleHost bundleHost, ResourceFile sourceDirectory) {
		this.bundleHost = bundleHost;
		this.sourceDir = sourceDirectory;
		this.symbolicName = BundleHost.getSymbolicNameFromSourceDir(sourceDir);
		this.binDir = GhidraScriptUtil.getCompiledBundlesDir().resolve(symbolicName);

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
		return GhidraScriptUtil.getCompiledBundlesDir().resolve(tmpSymbolicName);
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
		return sourceDir;
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
	 * @throws GhidraBundleException on failure to parse the \@imports tag
	 */
	private void updateRequirementsFromMetadata() throws GhidraBundleException {
		// parse metadata from all Java source in sourceDir
		buildReqs.clear();
		req2file.clear();

		for (ResourceFile rf : sourceDir.listFiles()) {
			if (rf.getName().endsWith(".java")) {
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

	List<BundleRequirement> getAllReqs() {
		Map<String, BundleRequirement> dedupedReqs = new HashMap<>();
		buildReqs.values().stream().flatMap(List::stream).forEach(
			r -> dedupedReqs.putIfAbsent(r.toString(), r));

		return new ArrayList<>(dedupedReqs.values());
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

	static private void wipe(Path path) throws IOException {
		if (Files.exists(path)) {
			for (Path p : (Iterable<Path>) Files.walk(path).sorted(
				Comparator.reverseOrder())::iterator) {
				Files.deleteIfExists(p);
			}
		}
	}

	private void wipeBinDir() throws IOException {
		wipe(binDir);
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

		long lastBundleActivation = 0; // XXX record last bundle activation in bundlestatusmodel
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
			writer.printf("%d new files, %d skipped, %s\n", newSourcecount, failing,
				newManifest ? ", new manifest" : "");

			// if there a bundle is currently active, uninstall it
			Bundle b = getBundle();
			if (b != null) {
				bundleHost.deactivateSynchronously(b);
			}

			// once we've committed to recompile and regenerate generated classes, delete the old stuff
			deleteOldBinaries();

			BundleCompiler bundleCompiler = new BundleCompiler(bundleHost);

			long startTime = System.nanoTime();
			bundleCompiler.compileToExplodedBundle(this, writer);
			long endTime = System.nanoTime();
			writer.printf("%3.2f seconds compile time.\n", (endTime - startTime) / 1e9);
			bundleHost.fireBundleBuilt(this);
			return true;
		}
		return false;
	}

	@Override
	public Bundle install() throws GhidraBundleException {
		return bundleHost.installFromLoc(getBundleLoc());
	}

	@Override
	public Bundle getBundle() throws GhidraBundleException {
		return bundleHost.getBundle(getBundleLoc());
	}

	@Override
	public void clean() {
		try {
			Bundle b = getBundle();
			if (b != null) {
				bundleHost.deactivateSynchronously(b);
			}
			wipeBinDir();
		}
		catch (IOException | GhidraBundleException | InterruptedException e) {
			Msg.showError(this, null, "source bundle clean error",
				"while attempting to delete the compiled directory, an exception was thrown", e);
		}
	}

	private static Predicate<String> bintail =
		Pattern.compile("(\\$.*)?\\.class", Pattern.CASE_INSENSITIVE).asMatchPredicate();

	private ResourceFile[] correspondingBinaries(ResourceFile source) {
		String parentPath = source.getParentFile().getAbsolutePath();
		String relpath = parentPath.substring(sourceDir.getAbsolutePath().length());
		if (relpath.startsWith(File.separator)) {
			relpath = relpath.substring(1);
		}
		String n0 = source.getName();
		final String n = n0.substring(0, n0.length() - 5);// trim .java
		ResourceFile bp = new ResourceFile(binDir.resolve(relpath).toFile());
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
			stack.add(sourceDir);
			while (!stack.isEmpty()) {
				ResourceFile sd = stack.pop();
				String relpath =
					sd.getAbsolutePath().substring(sourceDir.getAbsolutePath().length());
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
}
