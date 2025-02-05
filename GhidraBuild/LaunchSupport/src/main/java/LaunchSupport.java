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
import java.awt.GraphicsEnvironment;
import java.io.*;
import java.text.ParseException;
import java.util.List;

import javax.swing.JFileChooser;

import ghidra.launch.*;
import ghidra.launch.JavaFinder.JavaFilter;

/**
 * Tool that helps gather information needed to launch Ghidra/GhidraServer.  This is intended 
 * to be a helper for the launch scripts so that most of the "heavy-lifting" can be done in Java
 * rather than in OS-specific scripts.
 */
public class LaunchSupport {

	private static final int EXIT_SUCCESS = 0;
	private static final int EXIT_FAILURE = 1;

	/**
	 * {@link LaunchSupport} entry point.  Uses standard exit codes to tell the user if 
	 * the desired operation succeeded for failed.
	 * 
	 * @param args [INSTALL_DIR] [-java_home | -jdk_home | -vmargs | -java_home_check &lt;path&gt;] [-ask | -save]
	 * <ul>
	 *   <li><b>-java_home: </b> Get Java home (JDK or JRE) and output on stdout.</li>
	 *   <li><b>-jdk_home: </b> Get Java home (JDK only) and output on stdout.</li>
	 *   <li><b>-jdk_home_check: </b> Verify that the specified Java home directory contains a 
	 *                           supported version of java.  No output is produced.</li>
	 *   <li><b>-vmargs: </b> Get JVM arguments and output on stdout (one per line).</li>
	 * </ul>
	 * Optional arguments supported by -java_home and -jdk_home:
	 * <ul>
	 *   <li><b>-ask: </b> Interactively ask the user to choose a Java home.</li>
	 *   <li><b>-save: </b> Save Java home to file for future use.</li>
	 * </ul>
	 */
	public static void main(String[] args) {

		int exitCode = EXIT_FAILURE; // failure by default

		// Validate command line arguments
		if (args.length < 2 || args.length > 4) {
			System.err.println("LaunchSupport expected 2 to 4 arguments but got " + args.length);
			System.exit(exitCode);
		}

		// Parse command line arguments
		int argIx = 0;
		String installDirPath = args[argIx++];
		String mode = args[argIx++];
		String checkPath = null;
		if ("-java_home_check".equals(mode)) {
			checkPath = args[argIx++];
		}

		if (!"-java_home".equals(mode) && !"-jdk_home".equals(mode) && argIx != args.length) {
			System.err.println("LaunchSupport received illegal argument: " + args[argIx]);
			System.exit(exitCode);
		}

		boolean ask = false;
		boolean save = false;

		for (int i = argIx; i < args.length; i++) {
			if (args[i].equals("-ask")) {
				ask = true;
			}
			else if (args[i].equals("-save")) {
				save = true;
			}
			else {
				System.err.println("LaunchSupport received illegal argument: " + args[i]);
				System.exit(exitCode);
			}
		}

		try {

			File installDir = new File(installDirPath).getCanonicalFile(); // change relative path to absolute
			AppConfig appConfig = new AppConfig(installDir);
			JavaFinder javaFinder = JavaFinder.create();

			// Pass control to a mode-specific handler
			switch (mode.toLowerCase()) {
				case "-java_home":
					exitCode = handleJavaHome(appConfig, javaFinder, JavaFilter.ANY, ask, save);
					break;
				case "-java_home_check":
					if (appConfig.isSupportedJavaHomeDir(new File(checkPath), JavaFilter.ANY)) {
						exitCode = EXIT_SUCCESS;
					}
					break;
				case "-jdk_home":
					exitCode =
						handleJavaHome(appConfig, javaFinder, JavaFilter.JDK_ONLY, ask, save);
					break;
				case "-vmargs":
					exitCode = handleVmArgs(appConfig);
					break;
				default:
					System.err.println("LaunchSupport received illegal argument: " + mode);
					break;
			}
		}
		catch (Exception e) {
			System.err.println(e.getMessage());
		}

		System.exit(exitCode);
	}

	/**
	 * Handles figuring out a Java home directory to use for the launch.  If it is successfully 
	 * determined, an exit code that indicates success is returned.
	 * 
	 * @param appConfig The appConfig configuration that defines what we support.
	 * @param javaFinder The Java finder.
	 * @param javaFilter A filter used to restrict what kind of Java installations we search for.
	 * @param ask True to interact with the user to they can specify a Java home directory.
	 *   False if the Java home directory should be searched for and output on STDOUT once
	 *   discovered.
	 * @param save True if the determined Java home directory should get saved to a file. 
	 * @return A suggested exit code based on whether or not a Java home directory was 
	 *   successfully determined.
	 * @throws IOException if there was a disk-related problem.
	 */
	private static int handleJavaHome(AppConfig appConfig, JavaFinder javaFinder,
			JavaFilter javaFilter, boolean ask, boolean save) throws IOException {
		if (ask) {
			return askJavaHome(appConfig, javaFinder, javaFilter);
		}
		return findJavaHome(appConfig, javaFinder, javaFilter, save);
	}

	private static void logJavaHomeError(File javaHomeDir, boolean isError, String source) {
		String level = isError ? "ERROR: " : "WARNING: ";
		if (!javaHomeDir.isDirectory()) {
			System.err
					.println(level + source + " specifies non-existing directory: " + javaHomeDir);
		}
		else {
			System.err.println(
				level + source + " specifies unsupported java version: " + javaHomeDir);
		}
	}

	/**
	 * Handles finding a Java home directory to use for the launch.  If one is successfully 
	 * found, its path is printed to STDOUT and an exit code that indicates success is 
	 * returned.  Otherwise, nothing is printed to STDOUT and an error exit code is returned.
	 * 
	 * @param appConfig The application configuration that defines what we support.
	 * @param javaFinder The Java finder.
	 * @param javaFilter A filter used to restrict what kind of Java installations we search for.
	 * @param save True if the determined Java home directory should get saved to a file. 
	 * @return A suggested exit code based on whether or not a supported Java home directory was 
	 *   successfully determined.
	 * @throws IOException if there was a problem saving the java home to disk.
	 */
	private static int findJavaHome(AppConfig appConfig, JavaFinder javaFinder,
			JavaFilter javaFilter, boolean save) throws IOException {

		File javaHomeDir;
		LaunchProperties launchProperties = appConfig.getLaunchProperties();

		// PRIORITY 1: JAVA_HOME_OVERRIDE property
		// If a valid java home override is specified in the launch properties, use that.
		// Someone presumably wants to force that specific version.
		javaHomeDir = launchProperties.getJavaHomeOverride();
		if (appConfig.isSupportedJavaHomeDir(javaHomeDir, javaFilter)) {
			if (save) {
				appConfig.saveJavaHome(javaHomeDir);
			}
			System.out.println(javaHomeDir);
			return EXIT_SUCCESS;
		}
		if (javaHomeDir != null) {
			logJavaHomeError(javaHomeDir, true,
				launchProperties.getLaunchPropertiesFile().getAbsolutePath() + ", " +
					LaunchProperties.JAVA_HOME_OVERRIDE);
		}

		// PRIORITY 2: Java specified by JAVA_HOME environment
		String javaHome = System.getenv("JAVA_HOME");
		if (javaHome != null) {
			javaHomeDir = new File(javaHome);
			if (appConfig.isSupportedJavaHomeDir(javaHomeDir, javaFilter)) {
				System.out.println(javaHomeDir);
				return EXIT_SUCCESS;
			}
		}

		// PRIORITY 3: Java on PATH
		// This program (LaunchSupport) was started with the Java on the PATH. Try to use this one 
		// next because it is most likely the one that is being upgraded on the user's system.
		javaHomeDir = javaFinder.findSupportedJavaHomeFromCurrentJavaHome(appConfig, javaFilter);
		if (javaHomeDir != null) {
			if (save) {
				appConfig.saveJavaHome(javaHomeDir);
			}
			System.out.println(javaHomeDir);
			return EXIT_SUCCESS;
		}

		// PRIORITY 4: Last used Java
		// Check to see if a prior launch resulted in that Java being saved. If so, try to use that.
		javaHomeDir = appConfig.getSavedJavaHome();
		if (appConfig.isSupportedJavaHomeDir(javaHomeDir, javaFilter)) {
			System.out.println(javaHomeDir);
			return EXIT_SUCCESS;
		}

		// PRIORITY 5: Find all supported Java installations, and use the newest.
		List<File> javaHomeDirs =
			javaFinder.findSupportedJavaHomeFromInstallations(appConfig, javaFilter);
		if (!javaHomeDirs.isEmpty()) {
			javaHomeDir = javaHomeDirs.iterator().next();
			if (save) {
				appConfig.saveJavaHome(javaHomeDir);
			}
			System.out.println(javaHomeDir);
			return EXIT_SUCCESS;
		}

		// Issue warning about incompatible JAVA_HOME
		if (javaHome != null) {
			logJavaHomeError(new File(javaHome), false, "JAVA_HOME environment");
		}

		return EXIT_FAILURE;
	}

	/**
	 * Handles interacting with the user to choose a Java home directory to use for the launch.  
	 * If a valid Java home directory was successfully determined, it is saved to the user's
	 * Java home save file, and an exit code that indicates success is returned.
	 * 
	 * @param appConfig The application configuration that defines what we support.  
	 * @param javaFinder The Java finder.
	 * @param javaFilter A filter used to restrict what kind of Java installations we search for.
	 * * @return A suggested exit code based on whether or not a valid Java home directory was
	 *   successfully chosen.
	 * @throws IOException if there was a problem interacting with the user, or saving the java
	 *   home location to disk.
	 */
	private static int askJavaHome(AppConfig appConfig, JavaFinder javaFinder,
			JavaFilter javaFilter) throws IOException {

		String javaName = javaFilter.equals(JavaFilter.JDK_ONLY) ? "JDK" : "Java";
		String javaRange;
		int min = appConfig.getMinSupportedJava();
		int max = appConfig.getMaxSupportedJava();
		if (min == max) {
			javaRange = min + "";
		}
		else if (max == 0) {
			javaRange = min + "+";
		}
		else {
			javaRange = min + "-" + max;
		}

		System.out.println("******************************************************************");
		System.out
				.println(javaName + " " + javaRange + " (" + appConfig.getSupportedArchitecture() +
					"-bit) could not be found and must be manually chosen!");
		System.out.println("******************************************************************");

		File javaHomeDir = null;
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		while (true) {
			boolean supportsDialog =
				!GraphicsEnvironment.isHeadless() && !(javaFinder instanceof MacJavaFinder);
			System.out.print("Enter path to " + javaName + " home directory");
			System.out.print(supportsDialog ? " (ENTER for dialog): " : ": ");
			String line = in.readLine().trim();
			if (supportsDialog && line.isEmpty()) {
				System.out.println("Opening selection dialog...");
				JFileChooser chooser = new JFileChooser();
				chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				chooser.setDialogTitle("Choose a " + javaName + " home directory");
				if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					javaHomeDir = chooser.getSelectedFile();
				}
			}
			else if (!line.isEmpty()) {
				javaHomeDir = new File(line);
			}
			else {
				continue;
			}
			try {
				JavaVersion javaVersion = appConfig.getJavaVersion(javaHomeDir, javaFilter);
				if (appConfig.isJavaVersionSupported(javaVersion)) {
					break;
				}
				System.out.println(
					"Java version " + javaVersion + " is outside of supported range: [" +
						javaRange + " " + appConfig.getSupportedArchitecture() + "-bit]");
			}
			catch (FileNotFoundException e) {
				System.out.println(
					"Not a valid " + javaName + " home directory. " + e.getMessage() + "!");
			}
			catch (IOException | ParseException e) {
				System.out.println("Failed to verify Java version. " + e.getMessage() + "!");
			}
		}

		File javaHomeSaveFile = appConfig.saveJavaHome(javaHomeDir);
		System.out.println("Saved changes to " + javaHomeSaveFile);
		return EXIT_SUCCESS;
	}

	/**
	 * Handles getting the VM arguments. If they are successfully determined, they are printed
	 * to STDOUT as a new-line delimited string that can be parsed and added to the command line, 
	 * and an exit code that indicates success is returned. 
	
	 * @param appConfig The appConfig configuration that defines what we support.  
	 * @return A suggested exit code based on whether or not the VM arguments were successfully
	 *   gotten.
	 */
	private static int handleVmArgs(AppConfig appConfig) {
		if (appConfig.getLaunchProperties() == null) {
			System.err.println("Launch properties file was not specified!");
			return EXIT_FAILURE;
		}

		// Force newline style to make cross-platform parsing consistent
		appConfig.getLaunchProperties().getVmArgList().forEach(e -> System.out.print(e + "\r\n"));
		return EXIT_SUCCESS;
	}
}
