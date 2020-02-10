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
import java.util.*;

import org.apache.commons.collections4.map.LazyMap;
import org.apache.commons.lang3.StringUtils;

import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

/**
 * A utility class for managing script directories and ScriptInfo objects.
 */
public class GhidraScriptUtil {

	private static final String SCRIPTS_SUBDIR_NAME = "ghidra_scripts";
	private static final String DEV_SCRIPTS_SUBDIR_NAME = "developer_scripts";

	private static final String BIN_DIR_NAME = "bin";
	private static List<GhidraScriptProvider> providers = null;

	/**
	 * User's home scripts directory
	 */
	public static String USER_SCRIPTS_DIR = buildUserScriptsDirectory();

	/**
	 * The default compile output directory
	 */
	//@formatter:off
	public static String USER_SCRIPTS_BIN_DIR = 
							 Application.getUserSettingsDirectory() + File.separator +
							 "dev" + File.separator + 
							 SCRIPTS_SUBDIR_NAME + File.separator +  
							 BIN_DIR_NAME;
	//@formatter:on

	private static void createUserScriptsDirs() {
		File scriptsDir = new File(USER_SCRIPTS_DIR);
		scriptsDir.mkdirs();

		File binDir = new File(USER_SCRIPTS_BIN_DIR);
		binDir.mkdirs();
	}

	private static List<Path> scriptDirectoryPaths = new ArrayList<>();

	static Map<ResourceFile, ScriptInfo> scriptFileToInfoMap = new HashMap<>();

	static Map<String, List<ResourceFile>> scriptNameToFilesMap =
		LazyMap.lazyMap(new HashMap<String, List<ResourceFile>>(), () -> new ArrayList<>());

	static {
		createUserScriptsDirs();
		scriptDirectoryPaths = getDefaultScriptDirectories();
	}

	/** The last time a request was made to refresh */
	private static long lastRefreshRequestTimestamp = System.currentTimeMillis();

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
	 * Stores the time of the refresh request so that clients may later ask when the last 
	 * refresh took place.
	 */
	public static void refreshRequested() {
		lastRefreshRequestTimestamp = System.currentTimeMillis();
	}

	public static long getLastRefreshRequestTimestamp() {
		return lastRefreshRequestTimestamp;
	}

	/**
	 * Returns a list of the default script directories.
	 * @return a list of the default script directories
	 */
	public static List<Path> getDefaultScriptDirectories() {

		List<Path> pathsList = new ArrayList<>();

		addScriptPaths(pathsList, SCRIPTS_SUBDIR_NAME);
		addScriptPaths(pathsList, DEV_SCRIPTS_SUBDIR_NAME);

		Collections.sort(pathsList);

		// this one should always be first
		pathsList.add(0, new Path(new ResourceFile(USER_SCRIPTS_DIR), true, false, false));
		return pathsList;
	}

	private static void addScriptPaths(List<Path> pathsList, String directoryName) {
		Iterable<ResourceFile> files = Application.findModuleSubDirectories(directoryName);
		for (ResourceFile file : files) {
			pathsList.add(new Path(file, true, false, true));
		}
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
		ArrayList<ResourceFile> dirs = new ArrayList<>();
		for (Path path : scriptDirectoryPaths) {
			dirs.add(path.getPath());
		}
		return dirs;
	}

	/**
	 * Sets the script directories to the new paths.
	 * @param newPaths the new script directories
	 */
	public static void setScriptDirectories(List<Path> newPaths) {
		scriptDirectoryPaths = new ArrayList<>(newPaths);
	}

	/**
	 * Returns the PATH for the specified directory.
	 * @param directory the directory
	 * @return the path for the specified directory
	 */
	public static Path getScriptPath(ResourceFile directory) {
		if (directory.isDirectory()) {
			for (Path path : scriptDirectoryPaths) {
				if (path.getPath().equals(directory)) {
					return path;
				}
			}
		}
		return null;
	}

	/**
	 * Returns the output directory to which the given script file's generated .class file should
	 * be written
	 * @param scriptFile the script file
	 * @return the directory
	 */
	public static ResourceFile getScriptCompileOutputDirectory(ResourceFile scriptFile) {
		return new ResourceFile(USER_SCRIPTS_BIN_DIR);
	}

	static ResourceFile getClassFile(ResourceFile sourceFile, String rawName) {
		if (sourceFile != null) {
			// prefer resource files when they exist, as we know exactly which file we want to load
			return GhidraScriptUtil.getClassFileByResourceFile(sourceFile, rawName);
		}

		return getClassFileByName(rawName);
	}

	/**
	 * Uses the given {@link ResourceFile} to find its class file.  This method is needed
	 * due to the fact that we sometimes can find a class file in more than one location, 
	 * such as when using an installation version of Ghidra in the same environment as 
	 * a development version of Ghidra.  We get better debugging when we use the class file
	 * that is associated with the given source file.
	 * 
	 * @param sourceFile the source file for which to find the generated class file.
	 * @param rawName the name of the class, without file extension or path info.
	 * @return the class file generated from the given source file.
	 */
	static ResourceFile getClassFileByResourceFile(ResourceFile sourceFile, String rawName) {
		String javaAbsolutePath = sourceFile.getAbsolutePath();
		String classAbsolutePath = javaAbsolutePath.replace(".java", ".class");

		String path = rawName.replace('.', '/');
		String className = path + ".class";

		ResourceFile classFile =
			findClassFile(getDevelopmentScriptBinDirectories(), classAbsolutePath, className);
		if (classFile != null) {
			Msg.trace(GhidraScriptUtil.class,
				"Resource file " + sourceFile + " class found at " + classFile);
			return classFile;
		}

		ResourceFile defaultCompilerDirectory = getScriptCompileOutputDirectory(sourceFile);
		classFile =
			new ResourceFile(new File(defaultCompilerDirectory.getAbsolutePath(), className));
		if (classFile.exists()) {
			// This should always exist when we compile the script ourselves
			Msg.trace(GhidraScriptUtil.class,
				"Resource file " + sourceFile + " class found at " + classFile);
			return classFile;
		}

		classFile = findClassFile(getScriptBinDirectories(), classAbsolutePath, className);
		if (classFile != null) {
			Msg.trace(GhidraScriptUtil.class,
				"Resource file " + sourceFile + " class found at " + classFile);
			return classFile;
		}

		// default to a non-existent file
		return new ResourceFile(GhidraScriptUtil.USER_SCRIPTS_BIN_DIR + "/" + className);
	}

	private static ResourceFile getClassFileByName(String rawName) {
		String path = rawName.replace('.', '/');
		String className = path + ".class";

		//
		// Note: in this case, we *only* want to search the script bin dirs, as we do not want
		//       to find other class elements that may be in the development environment.  For 
		//       example, we do not want to find non-script classes in the development bin dirs, 
		//       as those are loaded by our parent class loader.  If we load them, then they will
		//       not be the same class instances.
		//
		Set<ResourceFile> matchingClassFiles = new HashSet<>();
		Collection<ResourceFile> userBinDirectories = GhidraScriptUtil.getScriptBinDirectories();
		for (ResourceFile file : userBinDirectories) {
			ResourceFile testFile = new ResourceFile(file, className);
			if (testFile.exists()) {
				matchingClassFiles.add(testFile);
			}
		}

		return maybeWarnAboutNameConflict(className, matchingClassFiles);
	}

	private static ResourceFile findClassFile(Collection<ResourceFile> binDirs,
			String classAbsolutePath, String className) {

		Set<ResourceFile> matchingClassFiles = new HashSet<>();
		for (ResourceFile binDir : binDirs) {
			ResourceFile binParentFile = binDir.getParentFile();
			String absoluteParentPath = binParentFile.getAbsolutePath();
			if (classAbsolutePath.startsWith(absoluteParentPath)) {
				ResourceFile potentialFile = new ResourceFile(binDir, className);
				if (potentialFile.exists()) {
					matchingClassFiles.add(potentialFile);
				}
			}
		}

		return maybeWarnAboutNameConflict(className, matchingClassFiles);
	}

	private static ResourceFile maybeWarnAboutNameConflict(String className,
			Set<ResourceFile> matchingClassFiles) {
		int matchCount = matchingClassFiles.size();
		if (matchCount == 1) {
			return matchingClassFiles.iterator().next();
		}
		else if (matchCount > 1) {

			//
			// Unusual Code: When running from Eclipse we need to use the class file that is
			//               in the Eclipse project's bin.  If not, then users cannot debug
			//               the scripts, as Eclipse doesn't know how to find the source.  This
			//               can happen when users link source into the scripts project.
			//               We don't know if we are running from Eclipse, which means that this
			//               will give out the wrong file in the case where we are not, but there
			//               happen to be two different class files with the same name.  
			//
			ResourceFile preferredFile = null;
			for (ResourceFile file : matchingClassFiles) {
				if (file.getParentFile()
						.getAbsolutePath()
						.equals(
							GhidraScriptUtil.USER_SCRIPTS_BIN_DIR)) {
					preferredFile = file;
					break;
				}
			}

			if (preferredFile == null) {
				// just pick one
				preferredFile = matchingClassFiles.iterator().next();
			}

			Msg.warn(GhidraScriptUtil.class, "Found " + matchCount + " class files named " +
				className + ".  Using: " + preferredFile);
			return preferredFile;
		}
		return null;
	}

	/**
	 * Returns the list of directories to which scripts are compiled.
	 * @return the list
	 * 
	 * @see #getScriptCompileOutputDirectory(ResourceFile)
	 */
	public static List<ResourceFile> getScriptBinDirectories() {
		return Arrays.asList(new ResourceFile(USER_SCRIPTS_BIN_DIR));
	}

	/**
	 * Returns a list of directories.  Development directories differ from standard script
	 * directories in that the former have a bin directory at a different location from 
	 * the latter, due to the setup of the development environment.
	 * 
	 * @return Returns a list of directories 
	 */
	static Collection<ResourceFile> getDevelopmentScriptBinDirectories() {
		if (!SystemUtilities.isInDevelopmentMode() || SystemUtilities.isInTestingMode()) {
			return Collections.emptyList();
		}

		Set<ResourceFile> dirs = new HashSet<>();
		for (Path path : scriptDirectoryPaths) {
			//
			// Assumed structure of script dir path:
			//    /some/path/Ghidra/Features/Module/ghidra_scripts
			// 
			// Desired path:
			//    /some/path/Ghidra/Features/Module/bin/scripts

			ResourceFile scriptDir = path.getPath();
			ResourceFile moduleDir = scriptDir.getParentFile();
			dirs.add(new ResourceFile(moduleDir, BIN_DIR_NAME + File.separator + "scripts"));
		}
		return dirs;
	}

	/**
	 * Deletes all script class files.
	 */
	public static void clean() {
		scriptFileToInfoMap.clear(); // clear our cache of old files
		scriptNameToFilesMap.clear();

		File userdir = new File(USER_SCRIPTS_DIR);
		File[] classFiles = userdir.listFiles(
			(FileFilter) pathname -> pathname.getName().toLowerCase().endsWith(".class"));
		for (File classFile : classFiles) {
			classFile.delete();
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
	 * Returns true if a ScriptInfo object exists for
	 * the specified script file.
	 * @param scriptFile the script file
	 * @return true if a ScriptInfo object exists
	 */
	public static boolean contains(ResourceFile scriptFile) {
		return scriptFileToInfoMap.containsKey(scriptFile);
	}

	/**
	 * Removes the ScriptInfo object for the specified file
	 * @param scriptFile the script file
	 */
	public static void unloadScript(ResourceFile scriptFile) {
		scriptFileToInfoMap.remove(scriptFile);

		Iterator<ResourceFile> iter = scriptNameToFilesMap.get(scriptFile.getName()).iterator();
		while (iter.hasNext()) {
			ResourceFile rFile = iter.next();
			if (scriptFile.equals(rFile)) {
				iter.remove();
				break;
			}
		}
	}

	/**
	 * Returns an iterator over all script info objects.
	 * @return an iterator over all script info objects
	 */
	public static Iterator<ScriptInfo> getScriptInfoIterator() {
		return scriptFileToInfoMap.values().iterator();
	}

	/**
	 * Returns the script info object for the specified script file
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

		List<ResourceFile> matchingFiles = scriptNameToFilesMap.get(name);
		matchingFiles.add(scriptFile);
		markAnyDuplicates(matchingFiles);

		return info;
	}

	private static void markAnyDuplicates(List<ResourceFile> files) {
		boolean isDuplicate = files.size() > 1;
		files.forEach(f -> scriptFileToInfoMap.get(f).setDuplicate(isDuplicate));
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
			ResourceFile parentDirectory, List<Path> scriptDirectories) throws IOException {
		String baseName = GhidraScriptConstants.DEFAULT_SCRIPT_NAME;
		String extension = provider.getExtension();
		return createNewScript(baseName, extension, parentDirectory, scriptDirectories);
	}

	private static ResourceFile createNewScript(String scriptName, String extension,
			ResourceFile parentDirctory, List<Path> scriptDirectories) throws IOException {
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
	private static ResourceFile findScriptFileInPaths(List<Path> scriptDirectories,
			String filename) {

		String validatedName = fixupName(filename);

		for (Path path : scriptDirectories) {
			ResourceFile file = new ResourceFile(path.getPath(), validatedName);
			if (file.exists()) {
				return file;
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

		ResourceFile file = findScriptFileInPaths(scriptDirectoryPaths, name);
		if (file == null) {
			return null;
		}

		return getScriptInfo(file); // this will cache the created info
	}

	public static List<ResourceFile> getAllScripts() {
		List<ResourceFile> scriptList = new ArrayList<>();
		for (Path dirPath : scriptDirectoryPaths) {
			updateAvailableScriptFilesForDirectory(scriptList, dirPath.getPath());
		}
		return scriptList;
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
	 * Looks through all of the current {@link ScriptInfo}s to see if one already exists with 
	 * the given name.
	 * @param scriptName The name to check
	 * @return true if the name is not taken by an existing {@link ScriptInfo}.
	 */
	public static boolean alreadyExists(String scriptName) {
		return getExistingScriptInfo(scriptName) != null;
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
		if (matchingFiles.isEmpty()) {
			return null;
		}
		return scriptFileToInfoMap.get(matchingFiles.get(0));
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

	/**
	 * Updates every known script's duplicate value. 
	 */
	public static void refreshDuplicates() {
		scriptNameToFilesMap.values().forEach(files -> {

			boolean isDuplicate = files.size() > 1;
			files.forEach(file -> scriptFileToInfoMap.get(file).setDuplicate(isDuplicate));
		});
	}
}
