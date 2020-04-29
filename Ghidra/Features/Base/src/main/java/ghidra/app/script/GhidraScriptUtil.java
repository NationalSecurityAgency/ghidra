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

import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.stream.Collectors;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.plugin.core.osgi.OSGiException;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;

/**
 * A utility class for managing script directories and ScriptInfo objects.
 */
public class GhidraScriptUtil {

	private static final String SCRIPTS_SUBDIR_NAME = "ghidra_scripts";
	private static final String DEV_SCRIPTS_SUBDIR_NAME = "developer_scripts";

	private static List<GhidraScriptProvider> providers = null;

	/**
	 * User's home scripts directory
	 */
	public static String USER_SCRIPTS_DIR = buildUserScriptsDirectory();

	static BundleHost _bundleHost;

	public static BundleHost getBundleHost() {
		return _bundleHost;
	}

	private static void setBundleHost(BundleHost bundleHost) {
		if (_bundleHost != null) {
			throw new RuntimeException("GhidraScriptUtil initialized multiple times!");
		}

		try {
			_bundleHost = bundleHost;
			_bundleHost.startFramework();
		}
		catch (OSGiException | IOException e) {
			e.printStackTrace();
			Msg.error(GhidraScript.class, "failed to initialize BundleHost", e);
		}
	}

	/**
	 * initialize state of GhidraScriptUtil with user, system paths, and optional extra system paths.
	 * 
	 * @param bundleHost the host to use 
	 * @param extraSystemPaths additional system paths for this run, can be null 
	 * 
	 */
	public static void initialize(BundleHost bundleHost, List<String> extraSystemPaths) {
		setBundleHost(bundleHost);
		if (extraSystemPaths != null) {
			for (String path : extraSystemPaths) {
				bundleHost.addGhidraBundle(new ResourceFile(path), true, true);
			}
		}

		bundleHost.addGhidraBundle(GhidraScriptUtil.getUserScriptDirectory(), true, false);
		bundleHost.addGhidraBundles(GhidraScriptUtil.getSystemScriptPaths(), true, true);
	}

	public static void dispose() {
		if (_bundleHost != null) {
			_bundleHost.dispose();
			_bundleHost = null;
		}
		providers = null;
	}

	/**
	 * Returns a list of the current script directories.
	 * @return a list of the current script directories
	 */
	public static List<ResourceFile> getScriptSourceDirectories() {
		return _bundleHost.getBundlePaths().stream().filter(ResourceFile::isDirectory).collect(
			Collectors.toList());
	}

	public static ResourceFile getSourceDirectoryContaining(ResourceFile sourceFile) {
		String sourcePath = sourceFile.getAbsolutePath();
		for (ResourceFile sourceDir : getScriptSourceDirectories()) {
			if (sourcePath.startsWith(sourceDir.getAbsolutePath() + File.separatorChar)) {
				return sourceDir;
			}
		}
		return null;
	}

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
	public static List<ResourceFile> getSystemScriptPaths() {
		List<ResourceFile> pathsList = new ArrayList<>();

		addScriptPaths(pathsList, SCRIPTS_SUBDIR_NAME);
		addScriptPaths(pathsList, DEV_SCRIPTS_SUBDIR_NAME);

		Collections.sort(pathsList);
		return pathsList;
	}

	public static ResourceFile getUserScriptDirectory() {
		return new ResourceFile(USER_SCRIPTS_DIR);
	}

	private static void addScriptPaths(List<ResourceFile> pathsList, String directoryName) {
		pathsList.addAll(Application.findModuleSubDirectories(directoryName));
	}

	/**
	 * Determine if the specified file is contained within the Ghidra installation.
	 * @param file script file or directory
	 * @return true if file contained within Ghidra installation area
	 */
	public static boolean isSystemScriptPath(ResourceFile file) {
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
			Msg.error(null, "Unexpected Exception: " + e.getMessage(), e);
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
		try {
			return Files.list(BundleHost.getOsgiDir()).filter(Files::isDirectory).map(
				x -> new ResourceFile(x.toFile())).collect(Collectors.toList());
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
	public synchronized static List<GhidraScriptProvider> getProviders() {
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
		String scriptFileName = scriptFile.getName().toLowerCase();

		for (GhidraScriptProvider provider : getProviders()) {
			if (scriptFileName.endsWith(provider.getExtension().toLowerCase())) {
				return provider;
			}
		}
		return null;
	}

	/**
	 * Returns true if a provider exists that can process the specified file.
	 * 
	 * @param scriptFile the script file
	 * @return true if a provider exists that can process the specified file
	 */
	public static boolean hasScriptProvider(ResourceFile scriptFile) {
		String scriptFileName = scriptFile.getName().toLowerCase();
		for (GhidraScriptProvider provider : getProviders()) {
			if (scriptFileName.endsWith(provider.getExtension().toLowerCase())) {
				return true;
			}
		}
		return false;
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
	 * Fixup name issues, such as package parts in the name and inner class names.
	 * <p>
	 * This method can handle names with or without '.java' at the end; names with 
	 * '$' (inner classes) and names with '.' characters for package separators
	 * 
	 * @param name the name of the script
	 * @return the name as a '.java' file path (with '/'s and not '.'s)
	 */
	static String fixupName(String name) {
		if (name.endsWith(".java")) {
			name = name.substring(0, name.length() - 5);
		}

		String path = name.replace('.', '/');
		int innerClassIndex = path.indexOf('$');
		if (innerClassIndex != -1) {
			path = path.substring(0, innerClassIndex);
		}
		return path + ".java";
	}

	static ResourceFile findScriptFileInPaths(
			Collection<ResourceFile> scriptDirectories,
			String filename) {

		String validatedName = fixupName(filename);

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

}
