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
package ghidra.framework;

import java.io.*;
import java.util.*;

import generic.jar.ClassModuleTree;
import generic.jar.ResourceFile;
import ghidra.util.*;
import ghidra.util.datastruct.LRUMap;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;
import utilities.util.reflection.ReflectionUtilities;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

/**
 * The Application class provides a variety of static convenience methods for accessing Application 
 * elements that can be used once the {@link #initializeApplication} call has been made.
 *
 * <p>In order to initialize an application, an {@link ApplicationLayout} and an 
 * {@link ApplicationConfiguration} must be provided.  The layout and configuration come in a
 * variety of flavors, and are what makes the Application class usable across a range of tools.
 *
 * <p>Example use case:
 * <pre>
 *   ApplicationLayout layout = new GhidraApplicationLayout();
 *   ApplicationConfiguration configuration = new GhidraApplicationConfiguration();
 *   Application.initalizeApplication(layout, configuration);
 * </pre>
 */
public class Application {

	private static final String JAR_EXTENSION = ".jar";
	private static final String DATA_DIRNAME = "data/";

	private static Application app;
	private static Throwable firstCreationThrowable;

	private ApplicationLayout layout;
	private ApplicationConfiguration configuration;
	private ClassModuleTree classModuleTree;
	private boolean loggingInitialized;
	private Map<String, List<ResourceFile>> fileExtensionCache = new LRUMap<>(5);

	/**
	 * Creates a new application object.  Application is a singleton so this is private.
	 * 
	 * @param layout The application layout to be used by this application.
	 * @param configuration The application configuration to be used by this application.
	 */
	private Application(ApplicationLayout layout, ApplicationConfiguration configuration) {
		this.layout = layout;
		this.configuration = configuration;
	}

	private void initialize() {

		// Create application's user directories
		try {
			layout.createUserDirs();
		}
		catch (IOException e) {
			throw new AssertException(e.getMessage());
		}

		// Set headless property
		String isHeadless = Boolean.toString(configuration.isHeadless());
		System.setProperty(SystemUtilities.HEADLESS_PROPERTY, isHeadless);
		System.setProperty("java.awt.headless", isHeadless);

		// Set "single jar mode" property
		System.setProperty(SystemUtilities.SINGLE_JAR_MODE_PROPERTY,
			Boolean.toString(layout.inSingleJarMode()));

		// Initialize universal ID generator
		UniversalIdGenerator.initialize();

		// Initialize logging.
		initializeLogging();

		// Install static factories
		installStaticFactories();

		// Set error display
		Msg.setErrorDisplay(configuration.getErrorDisplay());
	}

	/**
	 * Initializes the application.  The static methods of this class cannot be used until the
	 * application is initialized.  
	 * 
	 * @param layout The application layout to be used by the application.
	 * @param configuration The application configuration to be used by the application.
	 */
	public static void initializeApplication(ApplicationLayout layout,
			ApplicationConfiguration configuration) {
		if (app == null) {
			app = new Application(layout, configuration);
			app.initialize();
			configuration.initializeApplication();
			firstCreationThrowable = new AssertException("First call to initialize Application...");
		}
		else {
			throw new AssertException("Attempted to initialize the application more than once!",
				firstCreationThrowable);
		}
	}

	/**
	 * Checks to see if the application has been initialized.
	 * 
	 * @return true if the application has been initialized; otherwise, false.
	 */
	public static boolean isInitialized() {
		return app != null;
	}

	private void installStaticFactories() {
		TaskMonitor monitor = configuration.getTaskMonitor();
		monitor.setMessage("Installing static factories...");

		configuration.installStaticFactories();
	}

	private void initializeLogging() {
		if (configuration.isInitializeLogging()) {

			TaskMonitor monitor = configuration.getTaskMonitor();
			monitor.setMessage("Initializing logging system...");

			initializeLogging(configuration.getApplicationLogFile(),
				configuration.getScriptLogFile());
		}
	}

	/**
	 * If the Application was previously initialized with logging disabled, this method
	 * may be used to perform delayed logging initialization.  
	 * @param logFile application log file, if null the default <i>application.log</i> will be stored
	 * within the user's application settings directory
	 * @param scriptLogFile scripting log file, if null the default <i>script.log</i> will be stored
	 * within the user's application settings directory
	 * @throws AssertException if Application has not yet been initialized, or logging 
	 * was previously configured for the application.
	 */
	public static void initializeLogging(File logFile, File scriptLogFile) {
		checkAppInitialized();
		if (app.loggingInitialized) {
			throw new AssertException("Application logging has already been initialized");
		}
		app.loggingInitialized = true;

		if (logFile == null) {
			logFile = new File(app.layout.getUserSettingsDir(), "application.log");
		}
		if (scriptLogFile == null) {
			// Some clients pass null for the script file, as they do not support scripting.  In
			// that case, just have the system use the application log as the script log.  This 
			// prevents the logging system from creating an oddly named log file.
			scriptLogFile = logFile;
		}

		LoggingInitialization.setApplicationLogFile(logFile);
		LoggingInitialization.setScriptLogFile(scriptLogFile);
		LoggingInitialization.initializeLoggingSystem();
	}

	public static ApplicationLayout getApplicationLayout() {
		checkAppInitialized();
		return app.layout;
	}

	private GModule getModuleFromTreeMap(String className) {
		if (app.classModuleTree == null) {
			ResourceFile rootDir = app.layout.getApplicationRootDirs().iterator().next();
			ResourceFile ModuleClassMapFile = new ResourceFile(rootDir, "classModuleTree");
			try {
				app.classModuleTree = new ClassModuleTree(ModuleClassMapFile);
			}
			catch (IOException e) {
				throw new AssertException("Can't find module for " + className);
			}
		}
		String moduleName = app.classModuleTree.getModuleName(className);
		return app.layout.getModules().get(moduleName);
	}

	public static ResourceFile getModuleContainingResourceFile(ResourceFile file) {
		while (file != null) {
			if (ModuleUtilities.isModuleDirectory(file)) {
				return file;
			}
			file = file.getParentFile();
		}
		return null;
	}

	public static ResourceFile getModuleContainingClass(String className) {
		return app.getModuleForClass(className);
	}

	private void findJavaSourceDirectories(List<ResourceFile> list,
			ResourceFile moduleRootDirectory) {
		ResourceFile srcDir = new ResourceFile(moduleRootDirectory, "src");
		if (!srcDir.isDirectory()) {
			return;
		}
		for (ResourceFile file : srcDir.listFiles()) {
			if (!file.isDirectory()) {
				continue;
			}
			ResourceFile javaDir = new ResourceFile(file, "java");
			if (javaDir.isDirectory()) {
				list.add(javaDir);
			}
		}
	}

	private ResourceFile findModuleForJavaSource(String sourcePath) {

		List<ResourceFile> javaSrcDirectories = new ArrayList<>();

		Collection<ResourceFile> moduleRootDirectories = getModuleRootDirectories();
		for (ResourceFile moduleDirectory : moduleRootDirectories) {

			javaSrcDirectories.clear();
			findJavaSourceDirectories(javaSrcDirectories, moduleDirectory);

			for (ResourceFile javaSrcDir : javaSrcDirectories) {
				ResourceFile child = new ResourceFile(javaSrcDir, sourcePath);
				if (child.exists()) {
					return moduleDirectory;
				}
			}
		}

		return null;
	}

	private ResourceFile getModuleForClass(String className) {
		// get rid of nested class name(s) if present
		int dollar = className.indexOf('$');
		if (dollar != -1) {
			className = className.substring(0, dollar);
		}

		String path = className.replace('.', '/');
		String sourcePath = path + ".java";
		String classFilePath = path + ".class";

		if (inSingleJarMode()) {
			GModule gModule = getModuleFromTreeMap(classFilePath);
			return gModule == null ? null : gModule.getModuleRoot();
		}

		// we're running from a binary installation...so get our jar and go up one
		Class<?> callersClass;
		try {
			callersClass = Class.forName(className);
		}
		catch (ClassNotFoundException e) {
			// This can happen when we are being called from a script, which is not in the
			// classpath.  This file will not have a module anyway
			return null;
		}

		File sourceLocationForClass = SystemUtilities.getSourceLocationForClass(callersClass);
		if (sourceLocationForClass.isDirectory()) {
			return findModuleForJavaSource(sourcePath);
		}

		// we have a jar file, which implies a installed deployment (not development)
		SystemUtilities.assertTrue(sourceLocationForClass.getName().endsWith(JAR_EXTENSION),
			"Expected jar file but got: " + sourceLocationForClass.getAbsolutePath());

		// our jar file resides in the module/lib
		File moduleDirectory = sourceLocationForClass.getParentFile().getParentFile();

		// our jar file resides in the module/build/lib (i.e., tests executed by Gradle)
		if ("build".equals(moduleDirectory.getName())) {
			moduleDirectory = moduleDirectory.getParentFile();
		}

		// return the module directory (lib's parent)
		return new ResourceFile(moduleDirectory);
	}

	private List<ResourceFile> findFilesByExtension(String extension) {
		List<ResourceFile> list = fileExtensionCache.get(extension);
		if (list != null) {
			return list;
		}

		extension = verifyExtension(extension);
		list = new ArrayList<>();
		for (GModule module : app.layout.getModules().values()) {
			module.accumulateDataFilesByExtension(list, extension);
		}

		fileExtensionCache.put(extension, list);

		return list;
	}

	private ResourceFile findModuleDataFile(String relativePath) {
		String dataFilePath = DATA_DIRNAME + relativePath;
		for (GModule module : app.layout.getModules().values()) {
			ResourceFile foundFile = module.findModuleFile(dataFilePath);
			if (foundFile != null) {
				return foundFile;
			}
		}
		return null;
	}

	private List<ResourceFile> findFilesByExtensionInModule(String moduleName, String extension)
			throws IllegalArgumentException {
		extension = verifyExtension(extension);
		List<ResourceFile> list = new ArrayList<>();
		GModule gModule = app.layout.getModules().get(moduleName);
		if (gModule != null) {
			gModule.accumulateDataFilesByExtension(list, extension);
		}
		return list;
	}

	private List<ResourceFile> findModuleDirectories(String relativePath) {
		ArrayList<ResourceFile> result = new ArrayList<>();
		for (GModule module : app.layout.getModules().values()) {
			module.collectExistingModuleDirs(result, relativePath);
		}
		return result;
	}

	private ResourceFile getDataFileInModule(String relativeDataPath, String moduleName)
			throws FileNotFoundException {

		GModule module = app.layout.getModules().get(moduleName);
		if (module == null) {
			throw new FileNotFoundException("module not found: " + moduleName);
		}

		ResourceFile foundFile = module.findModuleFile(DATA_DIRNAME + relativeDataPath);

		if (foundFile == null) {
			throw new FileNotFoundException(
				"file " + relativeDataPath + " does not exist in module " + moduleName);
		}

		if (foundFile.isDirectory()) {
			throw new FileNotFoundException(
				foundFile.getAbsolutePath() + " is a directory (expecting file)");
		}
		return foundFile;

	}

	private ResourceFile getFileInModule(String relativePath, String moduleName)
			throws FileNotFoundException {

		GModule module = app.layout.getModules().get(moduleName);
		if (module == null) {
			throw new FileNotFoundException("module not found: " + moduleName);
		}

		ResourceFile foundFile = module.findModuleFile(relativePath);

		if (foundFile == null) {
			throw new FileNotFoundException(
				"file " + relativePath + " does not exist in module " + moduleName);
		}

		if (foundFile.isDirectory()) {
			throw new FileNotFoundException(
				foundFile.getAbsolutePath() + " is a directory (expecting file)");
		}
		return foundFile;

	}

	private static void checkAppInitialized() {
		if (app == null) {
			throw new AssertException("\nYou must call Application.initializeApplication() before" +
				" calling any static method on Application!\n");
		}
	}

	private ResourceFile getDataSubDirectoryInModule(String relativePath, String moduleName)
			throws IOException, FileNotFoundException {

		GModule module = app.layout.getModules().get(moduleName);
		if (module == null) {
			throw new FileNotFoundException("module not found: " + moduleName);
		}

		String relativeDataFilePath = DATA_DIRNAME + relativePath;
		ResourceFile foundDir = module.findModuleFile(relativeDataFilePath);

		if (foundDir == null) {
			throw new FileNotFoundException(
				relativeDataFilePath + " does not exist in module " + moduleName);
		}

		if (!foundDir.isDirectory()) {
			throw new IOException(foundDir.getAbsolutePath() + " is a file (expecting directory)");
		}
		return foundDir;

	}

	private ResourceFile getSubDirectoryInModule(String relativePath, String moduleName)
			throws IOException, FileNotFoundException {

		GModule module = app.layout.getModules().get(moduleName);
		if (module == null) {
			throw new FileNotFoundException("module not found: " + moduleName);
		}

		ResourceFile foundDir = module.findModuleFile(relativePath);

		if (foundDir == null) {
			throw new FileNotFoundException(
				relativePath + " does not exist in module " + moduleName);
		}

		if (!foundDir.isDirectory()) {
			throw new IOException(foundDir.getAbsolutePath() + " is a file (expecting directory)");
		}
		return foundDir;

	}

	private File getModuleFile(GModule module, String subdirPath, String exactFilename) {
		String filePath = subdirPath + "/" + exactFilename;
		ResourceFile foundFile = module.findModuleFile(filePath);
		if (foundFile != null) {
			return foundFile.getFile(true);
		}
		return null;
	}

	private File getModuleOSFile(String exactFilename, String moduleName) {

		GModule module = app.layout.getModules().get(moduleName);
		if (module == null) {
			return null;
		}

		File file = getModuleFile(module,
			"build/os/" + Platform.CURRENT_PLATFORM.getDirectoryName(), exactFilename);

		if (file == null) {
			file = getModuleFile(module, "os/" + Platform.CURRENT_PLATFORM.getDirectoryName(),
				exactFilename);
		}

		// Allow win32 to be used for win64 as fallback
		if (file == null && Platform.CURRENT_PLATFORM == Platform.WIN_64) {
			file = getModuleFile(module, "build/os/" + Platform.WIN_32.getDirectoryName(),
				exactFilename);
		}
		if (file == null && Platform.CURRENT_PLATFORM == Platform.WIN_64) {
			file = getModuleFile(module, "os/" + Platform.WIN_32.getDirectoryName(), exactFilename);
		}

		return file;
	}

	private File findModuleFile(String subdirPath, String exactFilename) {
		for (GModule module : app.layout.getModules().values()) {
			File file = getModuleFile(module, subdirPath, exactFilename);
			if (file != null) {
				return file;
			}
		}
		return null;
	}

	private File getOSFileInAnyModule(String path) throws FileNotFoundException {

		File file =
			findModuleFile("build/os/" + Platform.CURRENT_PLATFORM.getDirectoryName(), path);

		if (file == null) {
			file = findModuleFile("os/" + Platform.CURRENT_PLATFORM.getDirectoryName(), path);
		}

		// Allow win32 to be used for win64 as fallback
		if (file == null && Platform.CURRENT_PLATFORM == Platform.WIN_64) {
			file = findModuleFile("build/os/" + Platform.WIN_32.getDirectoryName(), path);
		}
		if (file == null && Platform.CURRENT_PLATFORM == Platform.WIN_64) {
			file = findModuleFile("os/" + Platform.WIN_32.getDirectoryName(), path);
		}

		if (file == null) {
			throw new FileNotFoundException("os/" + Platform.CURRENT_PLATFORM.getDirectoryName() +
				"/" + path + " does not exist");
		}
		return file;
	}

	private String verifyExtension(String extension) {
		SystemUtilities.assertTrue(!extension.contains("/"),
			"extension cannot contain / (path separator)");
		SystemUtilities.assertTrue(!extension.contains("\\"),
			"extension cannot contain \\ (path separator)");
		int dotIndex = extension.indexOf('.');
		SystemUtilities.assertTrue(dotIndex == -1 || dotIndex == 0,
			"extension can not contain a \".\" char other than at the beginning");
		return dotIndex == -1 ? "." + extension : extension;
	}

	/**
	 * Returns the module root directory that contains the class that called this method.
	 * @return the module root directory that contains the class that called this method.
	 */
	public static ResourceFile getMyModuleRootDirectory() {
		checkAppInitialized();
		String className = ReflectionUtilities.getClassNameOlderThan(Application.class);
		return app.getModuleForClass(className);
	}

	/**
	 * Returns the name of the application.
	 * @return the name of the application.
	 */
	public static String getName() {
		checkAppInitialized();
		return app.layout.getApplicationProperties().getApplicationName();
	}

	/**
	 * Returns the value of the give application property name.
	 * @param propertyName the name of the application property to retrieve.
	 * @return the value of the give application property name.
	 */
	public static String getApplicationProperty(String propertyName) {
		checkAppInitialized();
		return app.layout.getApplicationProperties().getProperty(propertyName);
	}

	/**
	 * Returns a list of the application root directories.  An application root directory is a
	 * directory containing one or more modules.  Applications support multiple application root
	 * directories so that it can contain modules that don't have a common file system root.  This
	 * is useful if the application contains modules from more than one source code repository.
	 * Application roots are returned in the order they appear in the classpath.
	 * @return a list of root directories containing modules for this application.
	 */
	public static Collection<ResourceFile> getApplicationRootDirectories() {
		checkAppInitialized();
		return app.layout.getApplicationRootDirs();
	}

	/** 
	 * Returns the application root directory.   An application root directory is a
	 * directory containing one or more modules.  In development mode there may be multiple 
	 * application root directories, which can be retrieved via 
	 * {@link #getApplicationRootDirectories()}.
	 * <p>
	 * In an installation of the application, there will only be one application root directory.
	 * <p>
	 * <b>Note:  Be sure you understand that there may be multiple application root
	 * directories in development mode.</b>  In general you should not be using this method for 
	 * searching for files yourself, but instead using 
	 * the various <code>find*</code> methods of this class.    
	 * 
	 * @return Returns the application root directory.
	 * @see #getApplicationRootDirectories()
	 */
	public static ResourceFile getApplicationRootDirectory() {
		checkAppInitialized();
		return app.layout.getApplicationRootDirs().iterator().next();
	}

	/**
	 * Returns the File containing the user configuration settings for this application.
	 * @return the File containing the user configuration settings for this application.
	 */
	public static File getUserSettingsDirectory() {
		checkAppInitialized();
		return app.layout.getUserSettingsDir();
	}

	/**
	 * Returns the temporary directory specific to the user and the application.
	 * Directory has name of &lt;username&gt;-&lt;appname&gt;
	 * This directory may be removed at system reboot or during periodic 
	 * system cleanup of unused temp files.
	 * This directory is specific to the application name but not the version.
	 * Resources stored within this directory should utilize some 
	 * form of access locking or unique naming.  Transient resources should be 
	 * deleted when no longer in use.
	 * @return temp directory
	 */
	public static File getUserTempDirectory() {
		checkAppInitialized();
		return app.layout.getUserTempDir();
	}

	/**
	 * Returns the cache directory specific to the user and the application.
	 * The intention is for directory contents to be preserved, however the 
	 * specific location is platform specific and contents may be removed when
	 * not in use and may in fact be the same directory the user temp directory.
	 * This directory is specific to the application name but not the version.
	 * Resources stored within this directory should utilize some 
	 * form of access locking and/or unique naming. 
	 * @return cache directory
	 */
	public static File getUserCacheDirectory() {
		checkAppInitialized();
		return app.layout.getUserCacheDir();
	}

	/**
	 * Returns a collection of all the module root directories. A module root directory is
	 * the top-level directory of a module.
	 * @return a collection of all the module root directories.
	 */
	public static Collection<ResourceFile> getModuleRootDirectories() {
		checkAppInitialized();

		List<ResourceFile> list = new ArrayList<>();
		Collection<GModule> values = app.layout.getModules().values();
		for (GModule gModule : values) {
			list.add(gModule.getModuleRoot());
		}
		return list;
	}

	/**
	 * Returns the installation directory.  In an installation, there is only one application root
	 * and its parent is the installation directory.  If not an installation, then this call doesn't
	 * really make sense, but it will return the parent of the first installation root.
	 * @return
	 */
	public static ResourceFile getInstallationDirectory() {
		checkAppInitialized();
		return app.layout.getApplicationInstallationDir();
	}

	/**
	 * Return the module root directory for the module with the given name.
	 * @param moduleName the name of the module.
	 * @return the module root directory for the module with the given name or null if not found.
	 */
	public static ResourceFile getModuleRootDir(String moduleName) {
		checkAppInitialized();
		GModule module = app.layout.getModules().get(moduleName);
		return module != null ? module.getModuleRoot() : null;
	}

	/**
	 * Returns true if this build was not built through the official build process, but instead
	 *  was created using the "buildLocal" call.
	 * @return true if this build was not built using the official build process.
	 */
	public static boolean isTestBuild() {
		checkAppInitialized();
		String value = app.layout.getApplicationProperties().getProperty(
			ApplicationProperties.TEST_RELEASE_PROPERTY);
		if (value == null) {
			return false;
		}
		return Boolean.parseBoolean(value);
	}

	/**
	 * Checks whether or not the application is in "single jar" mode.
	 * 
	 * @return true if the application is in "single jar" mode; otherwise, false.
	 */
	public static boolean inSingleJarMode() {
		checkAppInitialized();
		return app.layout.inSingleJarMode();
	}

	/**
	 * Returns the version of this build.
	 * @return the version of this build.
	 */
	public static String getApplicationVersion() {
		checkAppInitialized();
		return app.layout.getApplicationProperties().getApplicationVersion();
	}

	/**
	 * Returns the date this build was created.
	 * @return the date this build was created.
	 */
	public static String getBuildDate() {
		checkAppInitialized();
		return app.layout.getApplicationProperties().getApplicationBuildDate();
	}

	/**
	 * Returns the release name for this build.
	 * @return the application release name.
	 */
	public static String getApplicationReleaseName() {
		checkAppInitialized();
		return app.layout.getApplicationProperties().getApplicationReleaseName();
	}

	/**
	 * Return the source repository revisions used in the build process
	 * or null if not applicable.
	 * @return source revision map or null if not applicable
	 */
	public static Map<String, String> getApplicationSourceRevisions() {
		HashMap<String, String> revMap = null;
		Enumeration<Object> keys = app.layout.getApplicationProperties().keys();
		while (keys.hasMoreElements()) {
			Object key = keys.nextElement();
			if (!(key instanceof String)) {
				continue;
			}
			String keyStr = (String) key;
			if (keyStr.startsWith(ApplicationProperties.REVISION_PROPERTY_PREFIX)) {
				if (revMap == null) {
					revMap = new HashMap<>();
				}
				revMap.put(keyStr, app.layout.getApplicationProperties().getProperty(keyStr));
			}
		}
		return revMap;
	}

	/**
	 * Returns a collection of module library directories. Library directories are optional for a module.
	 * @return a collection of module library directories.
	 */
	public static Collection<ResourceFile> getLibraryDirectories() {
		checkAppInitialized();
		return ModuleUtilities.getModuleLibDirectories(app.layout.getModules());
	}

	/**
	 * Returns all files within any module's data directory that end with the given extension.
	 * @param extension the extension of files to be found.
	 * @return all files within any module's data directory that end with the given extension.
	 */
	public static List<ResourceFile> findFilesByExtensionInApplication(String extension) {
		checkAppInitialized();
		return app.findFilesByExtension(extension);
	}

	/**
	 * Finds the first file that exists with the relative path in any module.
	 * @param relativePath the path from the module root
	 * @return the first file that exists with the relative path in any module.
	 */
	public static ResourceFile findDataFileInAnyModule(String relativePath) {
		checkAppInitialized();
		return app.findModuleDataFile(relativePath);
	}

	/**
	 * Returns a list of all files with the given extension that are located in the module
	 * of the calling class.
	 * @param extension the filename extension for which to find file.s
	 * @return a list of all files with the given extension that are located in the module
	 * of the calling class.
	 */
	public static List<ResourceFile> findFilesByExtensionInMyModule(String extension) {
		ResourceFile MyModuleDir = getMyModuleRootDirectory();

		if (MyModuleDir == null) {
			return new ArrayList<>();
		}

		return findFilesByExtension(MyModuleDir.getName(), extension);
	}

	/**
	 * Returns a list of all files with the given extension that are located in the named module.
	 * @param moduleName the name of the module for which to look for files with the given extension.
	 * @param extension the filename extension for which to find file.s
	 * @return a list of all files with the given extension that are located in the named module.
	 */
	public static List<ResourceFile> findFilesByExtension(String moduleName, String extension)
			throws IllegalArgumentException {
		checkAppInitialized();
		return app.findFilesByExtensionInModule(moduleName, extension);
	}

	/**
	 * Returns a list of all directories in any module that have the given module relative path.  For
	 * example, a relative path of "foo/bar" will return all directories that are of the form
	 * {@code <module root>/data/foo/bar}
	 * @param relativePath the module relative path to search for.
	 * @return a list of all directories in any module that have the given module relative path.
	 */
	public static List<ResourceFile> findModuleSubDirectories(String relativePath) {
		checkAppInitialized();
		return app.findModuleDirectories(relativePath);
	}

	/**
	 * Returns the directory relative to the calling class's module's data directory.
	 * @param relativePath the path relative the module's data directory
	 * @throws FileNotFoundException if the directory does not exist.
	 * @throws IOException if an error occurred trying to access the directory.
	 */
	public static ResourceFile getModuleDataSubDirectory(String relativePath)
			throws FileNotFoundException, IOException {
		checkAppInitialized();
		ResourceFile moduleDirectory = getMyModuleRootDirectory();

		if (moduleDirectory == null) {
			throw new FileNotFoundException("Module root directory not found.");
		}

		return app.getDataSubDirectoryInModule(relativePath, moduleDirectory.getName());
	}

	/**
	 * Return the directory relative the the name module's data directory. (i.e. "/data" will
	 * be prepended to the given path)
	 * @param moduleName the name of the module. 
	 * @param relativePath the path relative to the module's data directory.
	 * @throws FileNotFoundException if the directory does not exist
	 * @throws IOException if an error occurred trying to access the directory.
	 */
	public static ResourceFile getModuleDataSubDirectory(String moduleName, String relativePath)
			throws FileNotFoundException, IOException {
		checkAppInitialized();
		return app.getDataSubDirectoryInModule(relativePath, moduleName);
	}

	/**
	 * Return the directory relative the the name module's directory.
	 * @param moduleName the name of the module. 
	 * @param relativePath the path relative to the module's root directory.
	 * @throws FileNotFoundException if the directory does not exist
	 * @throws IOException if an error occurred trying to access the directory.
	 */
	public static ResourceFile getModuleSubDirectory(String moduleName, String relativePath)
			throws FileNotFoundException, IOException {
		checkAppInitialized();
		return app.getSubDirectoryInModule(relativePath, moduleName);
	}

	/**
	 * Returns the file relative to the calling class's module's data directory
	 * @param relativeDataPath the path relative the to module's data directory
	 * @throws FileNotFoundException if the file or module does not exist.
	 */
	public static ResourceFile getModuleDataFile(String relativeDataPath)
			throws FileNotFoundException {
		ResourceFile moduleDirectory = getMyModuleRootDirectory();

		if (moduleDirectory == null) {
			throw new FileNotFoundException("Module root directory not found.");
		}

		return app.getDataFileInModule(relativeDataPath, moduleDirectory.getName());
	}

	/**
	 * Returns the file relative to the named module's data directory. (i.e. "data/" will
	 * be prepended to the give path)
	 * @param moduleName the name of the module.
	 * @param relativeDataPath the path relative to the module's data directory.
	 * @throws FileNotFoundException if the file does not exist.
	 */
	public static ResourceFile getModuleDataFile(String moduleName, String relativeDataPath)
			throws FileNotFoundException {
		checkAppInitialized();
		return app.getDataFileInModule(relativeDataPath, moduleName);
	}

	/**
	 * Returns the file relative to the named module's directory.
	 * @param moduleName the name of the module.
	 * @param relativePath the path relative to the module's data directory.
	 * @throws FileNotFoundException if the file does not exist.
	 */
	public static ResourceFile getModuleFile(String moduleName, String relativePath)
			throws FileNotFoundException {
		checkAppInitialized();
		return app.getFileInModule(relativePath, moduleName);
	}

	/**
	 * Returns the OS specific file within the given module with the given name.
	 * @param moduleName the name of the module
	 * @param exactFilename the name of the OS file within the module.
	 * @throws FileNotFoundException if the file does not exist.
	 */
	public static File getOSFile(String moduleName, String exactFilename)
			throws FileNotFoundException {
		File osFile = app.getModuleOSFile(exactFilename, moduleName);
		if (osFile != null) {
			return osFile;
		}
		throw new FileNotFoundException(
			"Could not find file " + exactFilename + " in module " + moduleName);
	}

	/**
	 * Returns the OS specific file in the calling class's module.
	 * @param exactFilename the name of the OS specific file.
	 * @throws FileNotFoundException if the file does not exist.
	 */
	public static File getOSFile(String exactFilename) throws FileNotFoundException {
		ResourceFile myModuleRootDirectory = getMyModuleRootDirectory();
		if (myModuleRootDirectory == null) {
			// not in a module; may be in a script?
			return app.getOSFileInAnyModule(exactFilename);
		}

		File moduleOSFile = app.getModuleOSFile(exactFilename, myModuleRootDirectory.getName());
		if (moduleOSFile != null) {
			return moduleOSFile;
		}

		// not in my module; check all modules
		return app.getOSFileInAnyModule(exactFilename);
	}
}
