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
	 * @param args [INSTALL_DIR] [-java_home | -jdk_home | -vmargs] [-ask | -save]
	 * <ul>
	 *   <li><b>-java_home: </b> Get Java home (JDK or JRE)</li>
	 *   <li><b>-jdk_home: </b> Get Java home (JDK only)</li>
	 *   <li><b>-vmargs: </b> Get JVM arguments</li>
	 *   <li><b>-ask: </b> Interactively ask the user to choose a Java home</li>
	 *   <li><b>-save: </b> Save Java home to file for future use</li>
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
		String installDirPath = args[0];
		String mode = args[1];
		boolean ask = false;
		boolean save = false;

		for (int i = 2; i < args.length; i++) {
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
			JavaConfig javaConfig = new JavaConfig(installDir);
			JavaFinder javaFinder = JavaFinder.create();

			// Pass control to a mode-specific handler
			switch (mode.toLowerCase()) {
				case "-java_home":
					exitCode = handleJavaHome(javaConfig, javaFinder, JavaFilter.ANY, ask, save);
					break;
				case "-jdk_home":
					exitCode =
						handleJavaHome(javaConfig, javaFinder, JavaFilter.JDK_ONLY, ask, save);
					break;
				case "-vmargs":
					exitCode = handleVmArgs(javaConfig);
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
	 * @param javaConfig The Java configuration that defines what we support.
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
	private static int handleJavaHome(JavaConfig javaConfig, JavaFinder javaFinder,
			JavaFilter javaFilter, boolean ask, boolean save) throws IOException {
		if (ask) {
			return askJavaHome(javaConfig, javaFinder, javaFilter);
		}
		return findJavaHome(javaConfig, javaFinder, javaFilter, save);
	}

	/**
	 * Handles finding a Java home directory to use for the launch.  If one is successfully 
	 * found, its path is printed to STDOUT and an exit code that indicates success is 
	 * returned.  Otherwise, nothing is printed to STDOUT and an error exit code is returned.
	 * 
	 * @param javaConfig The Java configuration that defines what we support.
	 * @param javaFinder The Java finder.
	 * @param javaFilter A filter used to restrict what kind of Java installations we search for.
	 * @param save True if the determined Java home directory should get saved to a file. 
	 * @return A suggested exit code based on whether or not a supported Java home directory was 
	 *   successfully determined.
	 * @throws IOException if there was a problem saving the java home to disk.
	 */
	private static int findJavaHome(JavaConfig javaConfig, JavaFinder javaFinder,
			JavaFilter javaFilter, boolean save) throws IOException {

		File javaHomeDir;
		LaunchProperties launchProperties = javaConfig.getLaunchProperties();

		// PRIORITY 1: JAVA_HOME_OVERRIDE property
		// If a valid java home override is specified in the launch properties, use that.
		// Someone presumably wants to force that specific version.
		javaHomeDir = launchProperties.getJavaHomeOverride();
		if (javaConfig.isSupportedJavaHomeDir(javaHomeDir, javaFilter)) {
			if (save) {
				javaConfig.saveJavaHome(javaHomeDir);
			}
			System.out.println(javaHomeDir);
			return EXIT_SUCCESS;
		}

		// PRIORITY 2: Java on PATH
		// This program (LaunchSupport) was started with the Java on the PATH. Try to use this one 
		// next because it is most likely the one that is being upgraded on the user's system.
		javaHomeDir = javaFinder.findSupportedJavaHomeFromCurrentJavaHome(javaConfig, javaFilter);
		if (javaHomeDir != null) {
			if (save) {
				javaConfig.saveJavaHome(javaHomeDir);
			}
			System.out.println(javaHomeDir);
			return EXIT_SUCCESS;
		}

		// PRIORITY 3: Last used Java
		// Check to see if a prior launch resulted in that Java being saved. If so, try to use that.
		javaHomeDir = javaConfig.getSavedJavaHome();
		if (javaConfig.isSupportedJavaHomeDir(javaHomeDir, javaFilter)) {
			System.out.println(javaHomeDir);
			return EXIT_SUCCESS;
		}

		// PRIORITY 4: Find all supported Java installations, and use the newest.
		List<File> javaHomeDirs =
			javaFinder.findSupportedJavaHomeFromInstallations(javaConfig, javaFilter);
		if (!javaHomeDirs.isEmpty()) {
			javaHomeDir = javaHomeDirs.iterator().next();
			if (save) {
				javaConfig.saveJavaHome(javaHomeDir);
			}
			System.out.println(javaHomeDir);
			return EXIT_SUCCESS;
		}

		return EXIT_FAILURE;
	}

	/**
	 * Handles interacting with the user to choose a Java home directory to use for the launch.  
	 * If a valid Java home directory was successfully determined, it is saved to the the user's
	 * Java home save file, and an exit code that indicates success is returned.
	 * 
	 * @param javaConfig The Java configuration that defines what we support.  
	 * @param javaFinder The Java finder.
	 * @param javaFilter A filter used to restrict what kind of Java installations we search for.
	 * * @return A suggested exit code based on whether or not a valid Java home directory was
	 *   successfully chosen.
	 * @throws IOException if there was a problem interacting with the user, or saving the java
	 *   home location to disk.
	 */
	private static int askJavaHome(JavaConfig javaConfig, JavaFinder javaFinder,
			JavaFilter javaFilter) throws IOException {

		String javaName = javaFilter.equals(JavaFilter.JDK_ONLY) ? "JDK" : "Java";
		String javaRange;
		int min = javaConfig.getMinSupportedJava();
		int max = javaConfig.getMaxSupportedJava();
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
		System.out.println(
			javaName + " " + javaRange + " (" + javaConfig.getSupportedArchitecture() +
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
				JavaVersion javaVersion = javaConfig.getJavaVersion(javaHomeDir, javaFilter);
				if (javaConfig.isJavaVersionSupported(javaVersion)) {
					break;
				}
				System.out.println(
					"Java version " + javaVersion + " is outside of supported range: [" +
						javaRange + " " + javaConfig.getSupportedArchitecture() + "-bit]");
			}
			catch (FileNotFoundException e) {
				System.out.println(
					"Not a valid " + javaName + " home directory. " + e.getMessage() + "!");
			}
			catch (IOException | ParseException e) {
				System.out.println("Failed to verify Java version. " + e.getMessage() + "!");
			}
		}

		File javaHomeSaveFile = javaConfig.saveJavaHome(javaHomeDir);
		System.out.println("Saved changes to " + javaHomeSaveFile);
		return EXIT_SUCCESS;
	}

	/**
	 * Handles getting the VM arguments. If they are successfully determined, they are printed
	 * to STDOUT as a string that can be added to the command line, and an exit code that 
	 * indicates success is returned. 
	
	 * @param javaConfig The Java configuration that defines what we support.  
	 * @return A suggested exit code based on whether or not the VM arguments were successfully
	 *   gotten.
	 */
	private static int handleVmArgs(JavaConfig javaConfig) {
		if (javaConfig.getLaunchProperties() == null) {
			System.out.println("Launch properties file was not specified!");
			return EXIT_FAILURE;
		}

		System.out.println(javaConfig.getLaunchProperties().getVmArgs());
		return EXIT_SUCCESS;
	}
}
