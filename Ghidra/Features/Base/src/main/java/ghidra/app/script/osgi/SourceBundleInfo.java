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

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

import org.osgi.framework.Bundle;
import org.osgi.framework.wiring.BundleRequirement;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.ScriptInfo;
import ghidra.app.script.osgi.BundleHost.BuildFailure;

/**
 * The SourceBundleInfo class is a cache of information for bundles built from source directories.
 */
public class SourceBundleInfo {
	private final BundleHost bundleHost;
	final private ResourceFile sourceDir;
	final String symbolicName;
	final private Path binDir;
	final private String bundleLoc;
	boolean foundNewManifest;

	final List<ResourceFile> newSources = new ArrayList<>();
	final List<Path> oldBin = new ArrayList<>();

	//// information indexed by source file

	final HashMap<ResourceFile, BuildFailure> buildErrors = new HashMap<>();
	final HashMap<ResourceFile, List<BundleRequirement>> buildReqs = new HashMap<>();
	final HashMap<String, List<ResourceFile>> req2file = new HashMap<>();

	// cached values parsed form @imports tags on default-package source files

	public SourceBundleInfo(BundleHost bundleHost, ResourceFile sourceDir) {
		this.bundleHost = bundleHost;
		this.sourceDir = sourceDir;
		this.symbolicName = BundleHost.getSymbolicNameFromSourceDir(sourceDir);
		this.binDir = GhidraScriptUtil.getCompiledBundlesDir().resolve(symbolicName);

		this.bundleLoc = "reference:file://" + getBinDir().toAbsolutePath().normalize().toString();

	}

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

	public ResourceFile getSourceDir() {
		return sourceDir;
	}

	public Path getBinDir() {
		return binDir;
	}

	public Bundle install() throws GhidraBundleException {
		return bundleHost.installFromLoc(getBundleLoc());
	}

	public void buildError(ResourceFile rf, String err) {
		BuildFailure f = buildErrors.computeIfAbsent(rf, x -> new BundleHost.BuildFailure());
		f.when = rf.lastModified();
		f.message.append(err);
	}

	public String getPreviousBuildErrors() {
		return buildErrors.values().stream().map(e -> e.message.toString()).collect(
			Collectors.joining());
	}

	/**
	 * update buildReqs based on \@imports tag in java files from the default package
	 * 
	 * @throws OSGiException on failure to parse the \@imports tag
	 */
	private void computeRequirements() throws OSGiException {
		// parse metadata from all Java source in sourceDir
		buildReqs.clear();
		req2file.clear();

		for (ResourceFile rf : sourceDir.listFiles()) {
			if (rf.getName().endsWith(".java")) {
				// NB: ScriptInfo will update field values if lastModified has changed since last time they were computed
				ScriptInfo si = GhidraScriptUtil.getScriptInfo(rf);
				String imps = si.getImports();
				if (imps != null && !imps.isEmpty()) {
					List<BundleRequirement> reqs = BundleHost.parseImports(imps);
					buildReqs.put(rf, reqs);
					for (BundleRequirement req : reqs) {
						req2file.computeIfAbsent(req.toString(), x -> new ArrayList<>()).add(rf);
					}
				}
			}
		}
	}

	public List<BundleRequirement> getAllReqs() {
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
	public void updateFromFilesystem(PrintWriter writer) throws IOException, OSGiException {
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

		computeRequirements();

		// remove source files that failed last time, haven't changed, and don't have new dependencies available
		Iterator<ResourceFile> it = newSources.iterator();
		while (it.hasNext()) {
			ResourceFile sf = it.next();
			BuildFailure f = buildErrors.get(sf);
			if (f != null) {
				if (f.when == sf.lastModified()) {
					List<BundleRequirement> r = buildReqs.get(sf);
					if (r == null || r.isEmpty() || !bundleHost.canResolveAll(r)) {
						it.remove();
						continue;
					}
				}
				// it's either new or worth trying again
				buildErrors.remove(sf);
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

	long lastCompileAttempt;

	public void compileAttempted() {
		lastCompileAttempt = System.currentTimeMillis();
	}

	public long getLastCompileAttempt() {
		return lastCompileAttempt;
	}

	String summary = "";

	public void setSummary(String summary) {
		this.summary = summary;
	}

	public void appendSummary(String s) {
		if (!summary.isEmpty()) {
			summary += ", " + s;
		}
		else {
			summary = s;
		}
	}

	public String getSummary() {
		return summary;
	}

	public Bundle getBundle() {
		return bundleHost.getBundle(getBundleLoc());
	}

	public String getBundleLoc() {
		return bundleLoc;
	}

}
