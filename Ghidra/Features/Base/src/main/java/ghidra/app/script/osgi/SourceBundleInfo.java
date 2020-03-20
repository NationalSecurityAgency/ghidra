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

public class SourceBundleInfo {
	/**
	 * 
	 */
	private final BundleHost bundle_host;
	final private ResourceFile sourceDir;
	final String symbolicName;
	final private Path binDir;
	final private String bundleLoc;

	//// information indexed by source file

	// XXX add separate missing requirements tracking
	final HashMap<ResourceFile, BuildFailure> buildErrors = new HashMap<>();

	// cached values parsed form @imports tags on default-package source files

	public SourceBundleInfo(BundleHost bundleHost, ResourceFile sourceDir) {
		bundle_host = bundleHost;
		this.sourceDir = sourceDir;
		this.symbolicName = BundleHost.getSymbolicNameFromSourceDir(sourceDir);
		this.binDir = BundleHost.getCompiledBundlesDir().resolve(symbolicName);

		this.bundleLoc = "reference:file://" + getBinDir().toAbsolutePath().normalize().toString();

	}

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

	public Bundle getBundle() {
		return bundle_host.getBundle(getBundleLoc());
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

	public Bundle install() throws GhidraBundleException {
		return bundle_host.installFromLoc(getBundleLoc());
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

	private void computeRequirements() throws OSGiException {
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

	long lastCompileAttempt;

	public void compileAttempted() {
		lastCompileAttempt = System.currentTimeMillis();
	}

	public long getLastCompileAttempt() {
		return lastCompileAttempt;
	}

}