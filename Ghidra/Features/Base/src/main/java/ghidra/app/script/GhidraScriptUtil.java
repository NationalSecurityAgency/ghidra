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
package ghidra.app.script;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.plugin.core.osgi.OSGiException;
import ghidra.app.plugin.core.script.GhidraScriptMgrPlugin;
import ghidra.app.util.headless.HeadlessAnalyzer;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import utilities.util.FileUtilities;

/**
 * A utility class for managing script directories and ScriptInfo objects.
 */
public class GhidraScriptUtil {
	/**
	 * User's home scripts directory
	 */
	public static String USER_SCRIPTS_DIR = buildUserScriptsDirectory();

	/**
	 * this instance is Ghidra's singleton, a reference is held here and in {@link GhidraScriptMgrPlugin}
	 */
	private static BundleHost bundleHost;

	private static final String SCRIPTS_SUBDIR_NAME = "ghidra_scripts";
	private static final String DEV_SCRIPTS_SUBDIR_NAME = "developer_scripts";

	private static List<GhidraScriptProvider> providers;

	// number of references from the GUI  to bundleHost
	private static AtomicInteger referenceCount = new AtomicInteger(0);

	/**
	 * @return the bundle host used for scripting
	 */
	public static BundleHost getBundleHost() {
		return bundleHost;
	}

	/**
	 * set the bundle host and start the framework
	 * 
	 * @param aBundleHost the bundle host
	 */
	private static void setBundleHost(BundleHost aBundleHost) {
		if (bundleHost != null) {
			throw new RuntimeException("GhidraScriptUtil initialized multiple times!");
		}

		try {
			bundleHost = aBundleHost;
			bundleHost.startFramework();
		}
		catch (OSGiException | IOException e) {
			Msg.error(GhidraScriptUtil.class, "Failed to initialize BundleHost", e);
		}
	}

	/**
	 * initialize state of GhidraScriptUtil with user, system paths, and optional extra system paths.
	 * 
	 * @param aBundleHost the host to use 
	 * @param extraSystemPaths additional system paths for this run, can be null 
	 * 
	 */
	public static void initialize(BundleHost aBundleHost, List<String> extraSystemPaths) {
		setBundleHost(aBundleHost);
		if (extraSystemPaths != null) {
			for (String path : extraSystemPaths) {
				bundleHost.add(new ResourceFile(path), true, true);
			}
		}

		bundleHost.add(getUserScriptDirectory(), true, false);
		bundleHost.add(getSystemScriptDirectories(), true, true);
	}

	/**
	 * dispose of the bundle host and providers list
	 */
	public static void dispose() {
		if (bundleHost != null) {
			bundleHost.dispose();
			bundleHost = null;
		}
		providers = null;
	}

	/**
	 * Returns a list of the current script directories.
	 * @return a list of the current script directories
	 */
	public static List<ResourceFile> getScriptSourceDirectories() {
		return bundleHost.getBundleFiles()
				.stream()
				.filter(ResourceFile::isDirectory)
				.collect(Collectors.toList());
	}

	/**
	 * Search the currently managed source directories for the given script file.
	 * 
	 * @param sourceFile the source file
	 * @return the source directory if found, or null if not
	 */
	public static ResourceFile findSourceDirectoryContaining(ResourceFile sourceFile) {
		for (ResourceFile sourceDir : getScriptSourceDirectories()) {
			if (FileUtilities.relativizePath(sourceDir, sourceFile) != null) {
				return sourceDir;
			}
		}
		Msg.error(GhidraScriptUtil.class,
			"Failed to find script in any script directory: " + sourceFile.toString());
		return null;
	}

	/**
	 * Search the currently managed scripts for one with the given name.
	 * 
	 * @param scriptName the name
	 * @return the first file found or null if none are found
	 */
	public static ResourceFile findScriptByName(String scriptName) {
		return findScriptFileInPaths(getScriptSourceDirectories(), scriptName);
	}

	/**
	 * User's home scripts directory. Some tests may override the default using the 
	 * SystemUtilities.USER_SCRIPTS_DIR system property.
	 * @return the path to the default user scripts directory
	 */
	private static String buildUserScriptsDirectory() {

		String root = System.getProperty("user.home");
		String override = System.getProperty(GhidraScriptConstants.USER_SCRIPTS_DIR_PROPERTY);
		if (override != null) {
			Msg.debug(GhidraScriptUtil.class, "Using Ghidra script source directory: " + root);
			root = override;
		}

		String sourcePath = root + File.separator + SCRIPTS_SUBDIR_NAME;
		return sourcePath;
	}

	/**
	 * Returns a list of the default script directories.
	 * @return a list of the default script directories
	 */
	public static List<ResourceFile> getSystemScriptDirectories() {
		List<ResourceFile> dirList = new ArrayList<>();

		addScriptDirectories(dirList, SCRIPTS_SUBDIR_NAME);
		addScriptDirectories(dirList, DEV_SCRIPTS_SUBDIR_NAME);

		Collections.sort(dirList);
		return dirList;
	}

	public static ResourceFile getUserScriptDirectory() {
		return new ResourceFile(USER_SCRIPTS_DIR);
	}

	private static void addScriptDirectories(List<ResourceFile> dirList, String directoryName) {
		dirList.addAll(Application.findModuleSubDirectories(directoryName));
	}

	/**
	 * Determine if the specified file is contained within the Ghidra installation.
	 * @param file script file or directory
	 * @return true if file contained within Ghidra installation area
	 */
	public static boolean isSystemScript(ResourceFile file) {
		return isSystemFile(file);
	}

	/**
	 * Determine if the specified file is contained within the Ghidra installation.
	 * @param file file or directory to check
	 * @return true if file is contained within Ghidra application root.
	 */
	private static boolean isSystemFile(ResourceFile file) {
		try {
			String filePath = file.getCanonicalPath().replace('\\', '/');
			if (filePath.startsWith(USER_SCRIPTS_DIR)) {
				// a script inside of the user scripts dir is not a 'system' script 
				return false;
			}

			Collection<ResourceFile> roots = Application.getApplicationRootDirectories();
			for (ResourceFile resourceFile : roots) {
				String installPath = resourceFile.getCanonicalPath().replace('\\', '/');
				if (filePath.startsWith(installPath)) {
					return true;
				}
			}
			return false;
		}
		catch (IOException e) {
			Msg.error(GhidraScriptUtil.class,
				"Failed to find file in system directories: " + file.toString(), e);
			return true;
		}
	}

	/**
	 * Returns the list of exploded bundle directories
	 * @return the list
	 * 
	 * @deprecated accessing class file directly precludes OSGi wiring according to requirements and capabilities 
	 */
	@Deprecated
	public static List<ResourceFile> getExplodedCompiledSourceBundlePaths() {

		try (Stream<Path> pathStream = Files.list(BundleHost.getOsgiDir())) {
			return pathStream.filter(Files::isDirectory)
					.map(x -> new ResourceFile(x.toFile()))
					.collect(Collectors.toList());
		}
		catch (IOException e) {
			Msg.showError(GhidraScriptUtil.class, null, "error",
				"error listing user osgi directory", e);
			return Collections.emptyList();
		}
	}

	/**
	 * Returns the base name give a script file.
	 * For example, given "C:\Temp\SomeClass.java",
	 * it will return "SomeClass".
	 * @param script the script
	 * @return the base name
	 */
	public static String getBaseName(ResourceFile script) {
		String name = script.getName();
		int pos = name.lastIndexOf('.');
		if (pos == -1) {
			return name;
		}
		return name.substring(0, pos);
	}

	/**
	 * Returns a list of all Ghidra script providers
	 * 
	 * @return a list of all Ghidra script providers
	 */
	// Note: this method is synchronized so that two threads do not try to create the list when null
	public static synchronized List<GhidraScriptProvider> getProviders() {
		if (providers == null) {
			List<GhidraScriptProvider> newProviders =
				new ArrayList<>(ClassSearcher.getInstances(GhidraScriptProvider.class));
			Collections.sort(newProviders);
			providers = newProviders;
		}
		return providers;
	}

	/**
	 * Returns the corresponding Ghidra script providers
	 * for the specified script file.
	 * @param scriptFile the script file
	 * @return the Ghidra script provider
	 */
	public static GhidraScriptProvider getProvider(ResourceFile scriptFile) {
		return findProvider(scriptFile.getName());
	}

	/**
	 * Returns true if a provider exists that can process the specified file.
	 * 
	 * @param scriptFile the script file
	 * @return true if a provider exists that can process the specified file
	 */
	public static boolean hasScriptProvider(ResourceFile scriptFile) {
		return findProvider(scriptFile.getName()) != null;
	}

	/**
	 * Find the provider whose extension matches the given filename extension.
	 * 
	 * @param fileName name of script file
	 * @return the first matching provider or null if no provider matches
	 */
	private static GhidraScriptProvider findProvider(String fileName) {
		fileName = fileName.toLowerCase();
		for (GhidraScriptProvider provider : getProviders()) {
			if (fileName.endsWith(provider.getExtension().toLowerCase())) {
				return provider;
			}
		}
		return null;
	}

	/**
	 * Creates a new script with a unique name using the specified provider in the 
	 * specified directory.
	 * @param provider   the Ghidra script provider
	 * @param parentDirectory  the directory where the new script will be created.
	 * @param scriptDirectories The list of directories containing scripts (used to find a 
	 *        unique name).
	 * @return the newly created script file
	 * @throws IOException if an i/o error occurs
	 */
	public static ResourceFile createNewScript(GhidraScriptProvider provider,
			ResourceFile parentDirectory, List<ResourceFile> scriptDirectories) throws IOException {
		String baseName = GhidraScriptConstants.DEFAULT_SCRIPT_NAME;
		String extension = provider.getExtension();
		return createNewScript(baseName, extension, parentDirectory, scriptDirectories);
	}

	private static ResourceFile createNewScript(String scriptName, String extension,
			ResourceFile parentDirctory, List<ResourceFile> scriptDirectories) throws IOException {
		String baseName = scriptName;
		String className = baseName + extension;

		// we want to pick a name that is unique in *any* of the script directories
		int counter = 1;
		boolean exists = findScriptFileInPaths(scriptDirectories, className) != null;
		while (exists) {
			baseName = scriptName + counter++;
			className = baseName + extension;
			exists = findScriptFileInPaths(scriptDirectories, className) != null;
			if (counter > 1000) {
				throw new IOException(
					"Unable to create new script file, temporary files exceeded.");
			}
		}

		return new ResourceFile(parentDirctory, className);
	}

	public static ScriptInfo newScriptInfo(ResourceFile file) {
		return new ScriptInfo(getProvider(file), file);
	}

	/**
	 * Fix script name issues for searching in script directories.
	 * If no provider can be identified, Java is assumed.
	 * 
	 * <p>This method is part of a poorly specified behavior that is due for future amendment.
	 * 
	 * <p>It is used by {@link GhidraScript#runScript(String)} methods, 
	 * {@link #createNewScript(String, String, ResourceFile, List)}, and by {@link HeadlessAnalyzer} for 
	 * {@code preScript} and {@code postScript}.  The intent was to allow some freedom in how a user specifies
	 * a script in two ways: 1) if the extension is omitted ".java" is assumed and 2) if a Java class name is
	 * given it's converted to a relative path.
	 *  
	 * @param name the name of the script
	 * @return the name as a file path
	 */
	@Deprecated
	static String fixupName(String name) {
		GhidraScriptProvider provider = findProvider(name);
		// assume Java if no provider matched
		if (provider == null) {
			name = name + ".java";
			provider = findProvider(".java");
		}
		return provider.fixupName(name);
	}

	static ResourceFile findScriptFileInPaths(Collection<ResourceFile> scriptDirectories,
			String name) {

		String validatedName = fixupName(name);

		for (ResourceFile resourceFile : scriptDirectories) {
			if (resourceFile.isDirectory()) {
				ResourceFile file = new ResourceFile(resourceFile, validatedName);
				if (file.exists()) {
					return file;
				}
			}
		}
		return null;
	}

	/**
	 * When running the GUI, {@link GhidraScriptUtil} manages a single {@link BundleHost} instance.
	 * 
	 * @return the BundleHost singleton
	 */
	public static BundleHost acquireBundleHostReference() {
		if (referenceCount.getAndIncrement() == 0) {
			initialize(new BundleHost(), null);
		}
		return bundleHost;
	}

	/**
	 * release the reference the BundleHost reference.  When no references remain, 
	 * {@link #dispose()} is called. 
	 */
	public static void releaseBundleHostReference() {
		if (referenceCount.getAndDecrement() == 1) {
			dispose();
		}
	}

}
