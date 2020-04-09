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
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

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

	private static List<ResourceFile> scriptBundlePaths = new ArrayList<>();

	private static Map<ResourceFile, ScriptInfo> scriptFileToInfoMap = new HashMap<>();

	private static Map<String, List<ResourceFile>> scriptNameToFilesMap = new HashMap<>();

	static {
		scriptBundlePaths = getSystemScriptPaths();
		scriptBundlePaths.add(0, getUserScriptDirectory());
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
	 * Returns a list of the current script directories.
	 * @return a list of the current script directories
	 */
	public static List<ResourceFile> getScriptSourceDirectories() {
		return scriptBundlePaths.stream().filter(ResourceFile::isDirectory).collect(
			Collectors.toList());
	}

	/**
	 * Sets the script bundle paths
	 * @param newPaths the new script bundle paths
	 */
	public static void setScriptBundlePaths(List<ResourceFile> newPaths) {
		scriptBundlePaths = new ArrayList<>(newPaths);
	}

	public static List<ResourceFile> getAllScripts() {
		List<ResourceFile> scriptList = new ArrayList<>();
		for (ResourceFile dirPath : scriptBundlePaths) {
			updateAvailableScriptFilesForDirectory(scriptList, dirPath);
		}
		return scriptList;
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
	 * clear ScriptInfo metadata cached by GhidraScriptUtil
	 */
	public static void clearMetadata() {
		scriptFileToInfoMap.clear(); // clear our cache of old files
		scriptNameToFilesMap.clear();
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
	 * Removes the ScriptInfo object for the specified file
	 * @param scriptFile the script file
	 */
	public static void removeMetadata(ResourceFile scriptFile) {
		scriptFileToInfoMap.remove(scriptFile);

		String name = scriptFile.getName();
		List<ResourceFile> files = scriptNameToFilesMap.get(name);
		if (files != null) {
			Iterator<ResourceFile> iter = files.iterator();
			while (iter.hasNext()) {
				ResourceFile rFile = iter.next();
				if (scriptFile.equals(rFile)) {
					iter.remove();
					break;
				}
			}
			if (files.isEmpty()) {
				scriptNameToFilesMap.remove(name);
			}
		}
	}

	/**
	 * get all scripts
	 * @return an iterable over all script info objects
	 */
	public static Iterable<ScriptInfo> getScriptInfoIterable() {
		return () -> scriptFileToInfoMap.values().iterator();
	}

	/**
	 * Returns the script info object for the specified script file,
	 * construct a new one if necessary.
	 * 
	 * Only call this method if you expect to be creating ScriptInfo objects.
	 * Prefer getExistingScriptInfo instead. 
	 * 
	 * @param scriptFile the script file
	 * @return the script info object for the specified script file
	 */
	public static ScriptInfo getScriptInfo(ResourceFile scriptFile) {
		ScriptInfo info = scriptFileToInfoMap.get(scriptFile);
		if (info != null) {
			return info;
		}

		GhidraScriptProvider gsp = getProvider(scriptFile);
		info = new ScriptInfo(gsp, scriptFile);
		scriptFileToInfoMap.put(scriptFile, info);
		String name = scriptFile.getName();

		List<ResourceFile> matchingFiles =
			scriptNameToFilesMap.computeIfAbsent(name, (n) -> new ArrayList<>());
		matchingFiles.add(scriptFile);
		markAnyDuplicates(matchingFiles);

		return info;
	}

	/**
	 * Returns true if a ScriptInfo object exists for
	 * the specified script file.
	 * @param scriptFile the script file
	 * @return true if a ScriptInfo object exists
	 */
	public static boolean containsMetadata(ResourceFile scriptFile) {
		return scriptFileToInfoMap.containsKey(scriptFile);
	}

	public static ScriptInfo getExistingScriptInfo(ResourceFile script) {
		ScriptInfo info = scriptFileToInfoMap.get(script);
		if (info == null) {
			String s = (script.exists() ? "" : "non") + "existing script" + script.toString() +
				" is missing info we thought was there";
			System.err.println(s);
			Msg.showError(GhidraScriptUtil.class, null, "ScriptInfo lookup", s);
		}
		return info;
	}

	/**
	 * Returns the existing script info for the given name.  The script environment limits 
	 * scripts such that names are unique.  If this method returns a non-null value, then the 
	 * name given name is taken.
	 * 
	 * @param scriptName the name of the script for which to get a ScriptInfo
	 * @return a ScriptInfo matching the given name; null if no script by that name is known to
	 *         the script manager
	 */
	public static ScriptInfo getExistingScriptInfo(String scriptName) {
		List<ResourceFile> matchingFiles = scriptNameToFilesMap.get(scriptName);
		if (matchingFiles == null || matchingFiles.isEmpty()) {
			return null;
		}
		return scriptFileToInfoMap.get(matchingFiles.get(0));
	}

	/**
	 * Looks through all of the current {@link ScriptInfo}s to see if one already exists with 
	 * the given name.
	 * @param scriptName The name to check
	 * @return true if the name is not taken by an existing {@link ScriptInfo}.
	 */
	public static boolean alreadyExists(String scriptName) {
		return getExistingScriptInfo(scriptName) != null;
	}

	private static void markAnyDuplicates(List<ResourceFile> files) {
		boolean isDuplicate = files.size() > 1;
		files.forEach(f -> scriptFileToInfoMap.get(f).setDuplicate(isDuplicate));
	}

	/**
	 * Updates every known script's duplicate value. 
	 */
	public static void refreshDuplicates() {
		scriptNameToFilesMap.values().forEach(files -> {
			boolean isDuplicate = files.size() > 1;
			files.forEach(file -> scriptFileToInfoMap.get(file).setDuplicate(isDuplicate));
		});
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

	/** Returns true if the given filename exists in any of the given directories */
	private static ResourceFile findScriptFileInPaths(List<ResourceFile> scriptDirectories,
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

	/**
	 * Uses the given name to find a matching script.  This method only works because of the
	 * limitation that all script names in Ghidra must be unique.  If the given name has multiple
	 * script matches, then a warning will be logged.
	 * 
	 * @param name The name for which to find a script
	 * @return The ScriptInfo that has the given name
	 */
	public static ScriptInfo findScriptByName(String name) {
		List<ResourceFile> matchingFiles = scriptNameToFilesMap.get(name);
		if (matchingFiles != null && !matchingFiles.isEmpty()) {
			ScriptInfo info = scriptFileToInfoMap.get(matchingFiles.get(0));
			if (matchingFiles.size() > 1) {
				Msg.warn(GhidraScriptUtil.class, "Found duplicate scripts for name: " + name +
					".  Binding to script: " + info.getSourceFile());
			}
			return info;
		}

		ResourceFile file = findScriptFileInPaths(scriptBundlePaths, name);
		if (file == null) {
			return null;
		}

		return getExistingScriptInfo(file); // this will cache the created info
	}

	private static void updateAvailableScriptFilesForDirectory(List<ResourceFile> scriptAccumulator,
			ResourceFile directory) {
		ResourceFile[] files = directory.listFiles();
		if (files == null) {
			return;
		}

		for (ResourceFile scriptFile : files) {
			if (scriptFile.isFile() && hasScriptProvider(scriptFile)) {
				scriptAccumulator.add(scriptFile);
			}
		}
	}

	/**
	 * Runs the specified script with the specified state
	 * 
	 * @param scriptState state representing environment variables that the script is able to access
	 * @param script  Script to be run
	 * @param writer the writer to which warning and error messages will be written
	 * @param originator the client class requesting the script run; used for logging
	 * @param monitor the task monitor
	 * @return  whether the script successfully completed running
	 */
	public static boolean runScript(GhidraState scriptState, GhidraScript script,
			PrintWriter writer, Object originator, TaskMonitor monitor) {

		ResourceFile srcFile = script.getSourceFile();
		String scriptName =
			srcFile != null ? srcFile.getAbsolutePath() : (script.getClass().getName() + ".class");

		try {
			Msg.info(originator, "SCRIPT: " + scriptName);
			script.execute(scriptState, monitor, writer);
			writer.flush();
		}
		catch (Exception exc) {
			Program prog = scriptState.getCurrentProgram();
			String path = (prog != null ? prog.getExecutablePath() : "Current program is null.");
			String logErrorMsg =
				path + "\nREPORT SCRIPT ERROR: " + scriptName + " : " + exc.getMessage();
			Msg.error(originator, logErrorMsg, exc);
			return false;
		}

		return true;
	}

}
