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
package ghidra.launch;

import java.io.*;
import java.text.ParseException;
import java.util.Properties;

import ghidra.launch.JavaFinder.JavaFilter;

/**
 * Class to determine and represent a required Java configuration, including minimum and maximum 
 * supported versions, compiler compliance level, etc.
 */
public class JavaConfig {

	private static final String LAUNCH_PROPERTIES_NAME = "launch.properties";
	private static final String JAVA_HOME_SAVE_NAME = "java_home.save";

	private LaunchProperties launchProperties;
	private File javaHomeSaveFile;

	private String applicationName; // example: Ghidra
	private String applicationVersion; // example: 9.0.1
	private String applicationReleaseName; // example: PUBLIC, DEV, etc
	private int minSupportedJava;
	private int maxSupportedJava;
	private String compilerComplianceLevel;

	/**
	 * Creates a new Java configuration for the given installation.
	 * 
	 * @param installDir The installation directory.
	 * @throws FileNotFoundException if a required file was not found. 
	 * @throws IOException if there was a problem reading a required file.
	 * @throws ParseException if there was a problem parsing a required file.
	 */
	public JavaConfig(File installDir) throws FileNotFoundException, IOException, ParseException {
		initApplicationProperties(installDir);
		initLaunchProperties(installDir);
		initJavaHomeSaveFile(installDir);
	}

	/**
	 * Gets the launch properties associated with this Java configuration.  Certain aspects of the
	 * Java configuration are stored in the launch properties.
	 * 
	 * @return The launch properties associated with this Java configuration.  Could be null if
	 *   this Java configuration does not use launch properties.
	 */
	public LaunchProperties getLaunchProperties() {
		return launchProperties;
	}

	/**
	 * Gets the Java configuration's minimum supported major Java version.
	 *  
	 * @return The Java configuration's minimum supported major Java version.
	 */
	public int getMinSupportedJava() {
		return minSupportedJava;
	}

	/**
	 * Gets the Java configuration's maximum supported major Java version.
	 *  
	 * @return The Java configuration's maximum supported major Java version.  If there is no
	 *   restriction, the value will be 0.
	 */
	public int getMaxSupportedJava() {
		return maxSupportedJava;
	}

	/**
	 * Gets the Java configuration's supported Java architecture.  All supported Java 
	 * configurations must have an architecture of <code>64</code>.
	 * 
	 * @return The Java configuration's supported Java architecture (64).  
	 */
	public int getSupportedArchitecture() {
		return 64;
	}

	/**
	 * Gets the Java configuration's compiler compliance level that was used to build the 
	 * associated installation.
	 * 
	 * @return The Java configuration's compiler compliance level.
	 */
	public String getCompilerComplianceLevel() {
		return compilerComplianceLevel;
	}

	/**
	 * Gets the Java home directory from the user's Java home save file.
	 * 
	 * @return The Java home directory from the user's Java home save file, or null if the file
	 *   does not exist or is empty.
	 * @throws IOException if there was a problem reading the Java home save file.
	 */
	public File getSavedJavaHome() throws IOException {
		try (BufferedReader reader = new BufferedReader(new FileReader(javaHomeSaveFile))) {
			String line = reader.readLine().trim();
			if (line != null && !line.isEmpty()) {
				return new File(line);
			}
		}
		catch (FileNotFoundException e) {
			// Fall through to return null
		}
		return null;
	}

	/**
	 * Saves the given Java home directory to the user's Java home save file.  If the save
	 * file does not exist, it will be created.
	 * 
	 * @param javaHomeDir The Java home directory to save.
	 * @return The user's Java home save file.
	 * @throws IOException if there was a problem saving to the file.
	 */
	public File saveJavaHome(File javaHomeDir) throws IOException {
		if (!javaHomeSaveFile.getParentFile().exists() &&
			!javaHomeSaveFile.getParentFile().mkdirs()) {
			throw new IOException(
				"Failed to create directory: " + javaHomeSaveFile.getParentFile());
		}

		try (PrintWriter writer = new PrintWriter(new FileWriter(javaHomeSaveFile))) {
			writer.println(javaHomeDir);
		}

		return javaHomeSaveFile;
	}

	/**
	 * Tests to see if the given directory is a supported Java home directory for this Java
	 * configuration.
	 * 
	 * @param dir The directory to test.
	 * @param javaFilter A filter used to restrict what kind of Java installations we support.
	 * @return True if the given directory is a supported Java home directory for this Java
	 *   configuration.
	 */
	public boolean isSupportedJavaHomeDir(File dir, JavaFilter javaFilter) {
		try {
			return isJavaVersionSupported(getJavaVersion(dir, javaFilter));
		}
		catch (IOException | ParseException e) {
			return false;
		}
	}

	/**
	 * Tests to see if the given Java version is supported by this Java launch configuration.
	 * 
	 * @param javaVersion The java version to check.
	 * @return True if the given Java version is supported by this Java launch configuration.
	 */
	public boolean isJavaVersionSupported(JavaVersion javaVersion) {
		if (javaVersion.getArchitecture() != getSupportedArchitecture()) {
			return false;
		}

		int major = javaVersion.getMajor();
		return major >= minSupportedJava &&
			(maxSupportedJava == 0 || major <= maxSupportedJava);
	}

	/**
	 * Gets the Java version of the given Java home directory.
	 * 
	 * @param javaHomeDir The Java home directory to get the version of.
	 * @param javaFilter A filter used to restrict what kind of Java installations we support.
	 * @return The Java version of the given Java home directory.
	 * @throws FileNotFoundException if the given directory is missing a required Java file
	 *   or directory based on the provided filter.  The exception's message will have more 
	 *   details.
	 * @throws IOException if there was a problem executing the java executable with the 
	 *   "-version" argument.
	 * @throws ParseException if the version string failed to parse.
	 */
	public JavaVersion getJavaVersion(File javaHomeDir, JavaFilter javaFilter)
			throws FileNotFoundException, IOException, ParseException {

		if (javaHomeDir == null) {
			throw new FileNotFoundException("Directory not specified");
		}

		if (!javaHomeDir.isDirectory()) {
			throw new FileNotFoundException("Not a directory");
		}

		File binDir = new File(javaHomeDir, "bin");
		if (!binDir.isDirectory()) {
			throw new FileNotFoundException("Missing bin directory");
		}

		File javaExecutable = null;
		File javacExecutable = null;
		for (File f : binDir.listFiles()) {
			if (f.getName().equals("java") || f.getName().equals("java.exe")) {
				javaExecutable = f;
			}
			if (f.getName().equals("javac") || f.getName().equals("javac.exe")) {
				javacExecutable = f;
			}
		}
		if (javaExecutable == null) {
			throw new FileNotFoundException("Missing java executable");
		}
		if (javaFilter.equals(JavaFilter.JDK_ONLY) && javacExecutable == null) {
			throw new FileNotFoundException("JDK is missing javac executable");
		}
		if (javaFilter.equals(JavaFilter.JRE_ONLY) && javacExecutable != null) {
			throw new FileNotFoundException("JRE should not have javac executable");
		}

		return runAndGetJavaVersion(javaExecutable);
	}

	/**
	 * Gets the version of the given Java executable from the output of running "java -version".
	 * 
	 * @param javaExecutable The Java executable to run and get the version of.
	 * @return The version of the given Java executable.
	 * @throws IOException if there was a problem executing the given Java executable with the 
	 *   "-version" argument.
	 * @throws ParseException if the version string failed to parse.
	 */
	private JavaVersion runAndGetJavaVersion(File javaExecutable)
			throws ParseException, IOException {
		String version = "";
		String arch = "";
		Process proc = Runtime.getRuntime().exec(new String[] { javaExecutable.getAbsolutePath(),
			"-XshowSettings:properties", "-version" });
		try (BufferedReader reader =
			new BufferedReader(new InputStreamReader(proc.getErrorStream()))) {
			String line;
			while ((version.isEmpty() || arch.isEmpty()) && (line = reader.readLine()) != null) {
				line = line.trim();

				String searchString = "java.version = ";
				if (line.startsWith(searchString)) {
					version = line.substring(searchString.length());
				}
				
				searchString = "sun.arch.data.model = ";
				if (line.startsWith(searchString)) {
					arch = line.substring(searchString.length());
				}
			}
		}
		if (version.isEmpty()) {
			throw new ParseException("Failed to find Java version", 0);
		}
		if (arch.isEmpty()) {
			throw new ParseException("Failed to find Java architecture", 0);
		}
		return new JavaVersion(version, arch);
	}

	/**
	 * Initializes the required application properties for the given installation.
	 * 
	 * @param installDir The Ghidra installation directory.  This is the directory that has the
	 *   "Ghidra" subdirectory in it.
	 * @throws FileNotFoundException if the application.properties file was not found. 
	 * @throws IOException if there was a problem reading the application.properties file.
	 * @throws ParseException if there was a problem parsing the required application properties.
	 */
	private void initApplicationProperties(File installDir) throws FileNotFoundException, IOException, ParseException {
		File applicationPropertiesFile = new File(installDir, "Ghidra/application.properties");
		if (!applicationPropertiesFile.isFile()) {
			throw new FileNotFoundException(
				"Application properties file does not exist: " + applicationPropertiesFile);
		}

		Properties applicationProperties = new Properties();
		try (FileInputStream fin = new FileInputStream(applicationPropertiesFile)) {
			applicationProperties.load(fin);
		}
		
		// Required properties
		applicationName = getDefinedProperty(applicationProperties, "application.name");
		applicationVersion = getDefinedProperty(applicationProperties, "application.version");
		applicationReleaseName =
			getDefinedProperty(applicationProperties, "application.release.name");
		compilerComplianceLevel =
			getDefinedProperty(applicationProperties, "application.java.compiler");
		try {
			minSupportedJava =
				Integer.parseInt(getDefinedProperty(applicationProperties, "application.java.min"));
		}
		catch (NumberFormatException e) {
			throw new ParseException(
				"Failed to parse application's minimum supported Java major verison", 0);
		}

		// Optional properties
		String max = applicationProperties.getProperty("application.java.max");
		if (max != null && !max.isEmpty()) {
			try {
				maxSupportedJava = Integer.parseInt(max);
			}
			catch (NumberFormatException e) {
				throw new ParseException(
					"Failed to parse application's maximum supported Java major verison", 0);
			}
		}
		else {
			maxSupportedJava = 0;
		}
	}

	/**
	 * Initializes the launch properties for the given installation.
	 *  
	 * @param installDir The Ghidra installation directory.  This is the directory that has the
	 *   "Ghidra" subdirectory in it.
	 * @throws FileNotFoundException if the given launch properties file does not exist.
	 * @throws IOException if there was a problem reading the given launch properties file.
	 * @throws ParseException if there was a problem parsing the given launch properties file.
	 */
	private void initLaunchProperties(File installDir)
			throws FileNotFoundException, IOException, ParseException {
		boolean isDev = new File(installDir, "build.gradle").isFile();

		// Get the required launch properties file
		File launchPropertiesFile = new File(installDir,
			(isDev ? "Ghidra/RuntimeScripts/Common/" : "") + "support/" + LAUNCH_PROPERTIES_NAME);
		if (!launchPropertiesFile.isFile()) {
			throw new FileNotFoundException(
				"Launch properties file does not exist: " + launchPropertiesFile);
		}

		launchProperties = new LaunchProperties(launchPropertiesFile);
	}

	/**
	 * Initializes the Java home save file.
	 *  
	 * @param installDir The Ghidra installation directory.  This is the directory that has the
	 *   "Ghidra" subdirectory in it.
	 * @throws FileNotFoundException if the user's home directory was not found.
	 */
	private void initJavaHomeSaveFile(File installDir) throws FileNotFoundException {
		boolean isDev = new File(installDir, "build.gradle").isFile();

		// Ensure there is a user home directory (there definitely should be)
		String userHomeDirPath = System.getProperty("user.home");
		if (userHomeDirPath == null || userHomeDirPath.isEmpty()) {
			throw new FileNotFoundException("User home directory is not known.");
		}
		File userHomeDir = new File(userHomeDirPath);
		if (!userHomeDir.isDirectory()) {
			throw new FileNotFoundException("User home directory does not exist: " + userHomeDir);
		}

		// Get the java home save file from user home directory (it might not exist yet).
		File userSettingsParentDir =
			new File(userHomeDir, "." + applicationName.replaceAll("\\s", "").toLowerCase());

		String userSettingsDirName = userSettingsParentDir.getName() + "_" + applicationVersion +
			"_" + applicationReleaseName.replaceAll("\\s", "").toUpperCase();

		if (isDev) {
			userSettingsDirName += "_location_" + installDir.getParentFile().getName();
		}

		File userSettingsDir = new File(userSettingsParentDir, userSettingsDirName);
		javaHomeSaveFile = new File(userSettingsDir, JAVA_HOME_SAVE_NAME);
	}

	/**
	 * Gets the property value with the given key.
	 * 
	 * @param properties The properties to get the property from.
	 * @param key The property's key. 
	 * @return The property's corresponding value.
	 * @throws ParseException if the property with the given key did not have a defined value.
	 */
	private String getDefinedProperty(Properties properties, String key) throws ParseException {
		String value = properties.getProperty(key);
		if (value == null || value.isEmpty()) {
			throw new ParseException("Property \"" + key + "\" is not defined.", 0);
		}
		return value;
	}
}
