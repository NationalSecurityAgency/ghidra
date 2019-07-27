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

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.*;

/**
 * Class responsible for finding Java installations on a system.
 */
public abstract class JavaFinder {

	/**
	 * A filter used to restrict what kind of Java installations we search for.
	 */
	public enum JavaFilter {
		JRE_ONLY, JDK_ONLY, ANY
	}

	/**
	 * The different supported platforms (operating systems).
	 */
	public enum Platform {
		WINDOWS, MACOS, LINUX;
	}

	/**
	 * Gets the current {@link Platform}.
	 * 
	 * @return The current {@link Platform}
	 */
	public static Platform getCurrentPlatform() {
		String os = System.getProperty("os.name");
		if (os != null) {
			os = os.toLowerCase();
			if (os.contains("win")) {
				return Platform.WINDOWS;
			}
			if (os.contains("mac")) {
				return Platform.MACOS;
			}
		}
		return Platform.LINUX;
	}

	/**
	 * Creates a Java finder to use for the current {@link Platform platform}.
	 * 
	 * @return The Java finder to use for the current {@link Platform platform}
	 */
	public static JavaFinder create() {
		switch (getCurrentPlatform()) {
			case WINDOWS:
				return new WindowsJavaFinder();
			case MACOS:
				return new MacJavaFinder();
			case LINUX:
			default:
				return new LinuxJavaFinder();
		}
	}

	/**
	 * Returns a list of supported Java home directories from discovered Java installations.
	 * The list is sorted from newest Java version to oldest.
	 * 
	 * @param javaConfig The Java configuration that defines what we support.
	 * @param javaFilter A filter used to restrict what kind of Java installations we search for.
	 * @return A sorted list of supported Java home directories from discovered Java installations.
	 */
	public List<File> findSupportedJavaHomeFromInstallations(JavaConfig javaConfig,
			JavaFilter javaFilter) {
		Set<File> potentialJavaHomeSet = new TreeSet<>();
		for (File javaRootInstallDir : getJavaRootInstallDirs()) {
			if (javaRootInstallDir.isDirectory()) {
				for (File dir : javaRootInstallDir.listFiles()) {
					if (dir.isDirectory()) {
						dir = new File(dir, getJavaHomeSubDirPath());
						if (javaFilter.equals(JavaFilter.ANY) ||
							javaFilter.equals(JavaFilter.JDK_ONLY)) {
							potentialJavaHomeSet.add(getJdkHomeFromJavaHome(dir));
						}
						if (javaFilter.equals(JavaFilter.ANY) ||
							javaFilter.equals(JavaFilter.JRE_ONLY)) {
							potentialJavaHomeSet.add(getJreHomeFromJavaHome(dir));
						}
					}
				}
			}
		}
		final Map<File, JavaVersion> javaHomeToVersionMap = new HashMap<>();
		for (File potentialJavaHomeDir : potentialJavaHomeSet) {
			try {
				JavaVersion javaVersion =
					javaConfig.getJavaVersion(potentialJavaHomeDir, javaFilter);
				if (javaConfig.isJavaVersionSupported(javaVersion)) {
					javaHomeToVersionMap.put(potentialJavaHomeDir, javaVersion);
				}
			}
			catch (ParseException | IOException e) {
				// skip it
			}
		}
		List<File> javaHomeDirs = new ArrayList<>(javaHomeToVersionMap.keySet());
		Collections.sort(javaHomeDirs, new Comparator<File>() {
			@Override
			public int compare(File dir1, File dir2) {
				return javaHomeToVersionMap.get(dir2).compareTo(javaHomeToVersionMap.get(dir1));
			}
		});
		return javaHomeDirs;
	}

	/**
	 * Returns the Java home directory corresponding to the current "java.home" system
	 * property (if it supported).
	 * 
	 * @param javaConfig The Java configuration that defines what we support.
	 * @param javaFilter A filter used to restrict what kind of Java installations we search for.
	 * @return The Java home directory corresponding to the current "java.home" system property.
	 *   Could be null if the current "java.home" is not supported.
	 */
	public File findSupportedJavaHomeFromCurrentJavaHome(JavaConfig javaConfig,
			JavaFilter javaFilter) {
		Set<File> potentialJavaHomeSet = new HashSet<>();
		String javaHomeProperty = System.getProperty("java.home");
		if (javaHomeProperty != null && !javaHomeProperty.isEmpty()) {
			File dir = new File(javaHomeProperty);
			if (javaFilter.equals(JavaFilter.ANY) || javaFilter.equals(JavaFilter.JDK_ONLY)) {
				potentialJavaHomeSet.add(getJdkHomeFromJavaHome(dir));
			}
			if (javaFilter.equals(JavaFilter.ANY) || javaFilter.equals(JavaFilter.JRE_ONLY)) {
				potentialJavaHomeSet.add(getJreHomeFromJavaHome(dir));
			}
			for (File potentialJavaHomeDir : potentialJavaHomeSet) {
				try {
					if (javaConfig.isJavaVersionSupported(
						javaConfig.getJavaVersion(potentialJavaHomeDir, javaFilter))) {
						return potentialJavaHomeDir;
					}
				}
				catch (ParseException | IOException e) {
					// skip it
				}
			}
		}
		return null;
	}

	/**
	 * Gets a list of possible Java root installation directories.
	 * 
	 * @return A list of possible Java root installation directories.
	 */
	protected abstract List<File> getJavaRootInstallDirs();

	/**
	 * Gets the sub-directory path of a Java root installation directory where the Java
	 * home lives.  For example, for OS X, this is "Contents/Home".  For other OS's, it may
	 * just be the empty string.
	 * 
	 * @return The sub-directory path of a Java root installation directory where the Java
	 *   home lives.
	 */
	protected abstract String getJavaHomeSubDirPath();

	/**
	 * Gets the JRE home directory corresponding to the given Java home directory.
	 * <p>
	 * If the Java home directory corresponds to a JDK, there is usually a corresponding
	 * JRE somewhere either in the JDK directory, or adjacent to it.
	 * 
	 * @param javaHomeDir The Java home directory.
	 * @return The JRE home directory corresponding to the given Java home directory.  Could
	 *   be the same directory if the given Java home is a JRE.
	 */
	protected abstract File getJreHomeFromJavaHome(File javaHomeDir);

	/**
	 * Gets the JDK home directory corresponding to the given Java home directory.
	 * <p>
	 * Often, the java from the PATH will run from a JRE bin directory instead of a JDK
	 * bin directory.  However, we can look in expected places to find the corresponding
	 * JDK home directory. 
	 * 
	 * @param javaHomeDir The Java home directory.
	 * @return The JDK home directory corresponding to the given Java home directory.  Could
	 *   be the same directory if the given Java home is a JDK.
	 */
	protected abstract File getJdkHomeFromJavaHome(File javaHomeDir);
}
