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
import java.text.SimpleDateFormat;
import java.util.*;

import generic.jar.ResourceFile;

/**
 * The application properties.  Application properties may either be stored on disk, or created
 * dynamically.
 */
public class ApplicationProperties extends Properties {

	/**
	 * The name of the application properties file.
	 */
	public static final String PROPERTY_FILE = "application.properties";

	/**
	 * The application name.  For example, "Ghidra".
	 */
	public static final String APPLICATION_NAME_PROPERTY = "application.name";

	/**
	 * The application version.  For example, "7.4.2".
	 * 
	 * @see ApplicationVersion
	 */
	public static final String APPLICATION_VERSION_PROPERTY = "application.version";

	/**
	 * The application's layout version.  The layout version should get incremented any time
	 * something changes about the application that could affect external tools that need to 
	 * navigate the application in some way (such as the Eclipse GhidraDev plugin).
	 * For example, "1".
	 */
	public static final String APPLICATION_LAYOUT_VERSION_PROPERTY = "application.layout.version";

	/**
	 * The minimum version of gradle required to build the application.
	 */
	public static final String APPLICATION_GRADLE_MIN_PROPERTY = "application.gradle.min";

	/**
	 * The minimum major version of Java required to run the application. For example, "8".
	 */
	public static final String APPLICATION_JAVA_MIN_PROPERTY = "application.java.min";

	/**
	 * The maximum major version of Java the application will run under. For example, "8".
	 * <p>
	 * If all versions of Java greater than {@link #APPLICATION_JAVA_MIN_PROPERTY} are
	 * supported, this property should not be set.
	 */
	public static final String APPLICATION_JAVA_MAX_PROPERTY = "application.java.max";

	/**
	 * The Java compiler compliance level that was used to build the application.
	 * For example, "1.8".
	 */
	public static final String APPLICATION_JAVA_COMPILER_PROPERTY = "application.java.compiler";

	/**
	 * The date the application was built on, in a long format.
	 * For example, "2018-Jan-11 1346 EST".
	 */
	public static final String BUILD_DATE_PROPERTY = "application.build.date";

	/**
	 * The date the application was built on, it a short format. For example, "20180111".
	 */
	public static final String BUILD_DATE_SHORT_PROPERTY = "application.build.date.short";

	/**
	 * The application's release name.  For example, "U".
	 */
	public static final String RELEASE_NAME_PROPERTY = "application.release.name";

	/**
	 * The application's release marking.
	 */
	public static final String RELEASE_MARKING_PROPERTY = "application.release.marking";

	/**
	 * Property prefix for dynamically generated version control revision number properties. 
	 */
	public static final String REVISION_PROPERTY_PREFIX = "application.revision.";

	public static final String TEST_RELEASE_PROPERTY = "application.test.release";
	public static final String RELEASE_SOURCE_PROPERTY = "application.release.source";

	/**
	 * Attempts to create an instance of this class by looking for the a properties file 
	 * with the give name in the current working directory.  
	 * 
	 * @param filename the name of the properties file to load
	 * @return the new instance of this class created from the properties file on disk
	 * @throws IOException if there is no properties file found in the expected location
	 */
	public static ApplicationProperties fromFile(String filename) throws IOException {

		String workingDir = System.getProperty("user.dir");
		if (workingDir == null) {
			throw new FileNotFoundException("Cannot determing the current working directory");
		}

		File dir = new File(workingDir);
		if (!dir.exists()) {
			throw new FileNotFoundException("Current working directory does not exist: " + dir);
		}

		File propsFile = new File(dir, filename);
		if (!propsFile.exists()) {
			throw new FileNotFoundException("No '" + filename + "' file found in " + workingDir);
		}

		ResourceFile resourceFile = new ResourceFile(propsFile);
		ApplicationProperties properties = new ApplicationProperties(resourceFile);
		return properties;
	}

	/**
	 * Creates a new application properties with the given name. Additional properties
	 * may be set with {@link #setProperty}.
	 * 
	 * @param name The application's name.
	 */
	public ApplicationProperties(String name) {
		setProperty(APPLICATION_NAME_PROPERTY, name);
	}

	/**
	 * Creates a new application properties with the given name and version. Additional properties
	 * may be set with {@link #setProperty}.
	 * 
	 * @param name The application's name.
	 * @param version The application's version.
	 * @param releaseName The application's release name.
	 */
	public ApplicationProperties(String name, String version, String releaseName) {
		Objects.requireNonNull(name, "Application name cannot be null");
		setProperty(APPLICATION_NAME_PROPERTY, name);

		Objects.requireNonNull(releaseName, "Release name cannot be null");
		setProperty(RELEASE_NAME_PROPERTY, releaseName);

		if (version != null) {
			setProperty(APPLICATION_VERSION_PROPERTY, version);
		}
	}

	/**
	 * Creates a new application properties from the given application properties file.
	 * 
	 * @param appPropertiesFile The application properties file.
	 * @throws IOException If there was a problem loading/reading a discovered properties file.
	 */
	public ApplicationProperties(ResourceFile appPropertiesFile) throws IOException {

		if (!appPropertiesFile.exists()) {
			throw new FileNotFoundException(
				"application.properties file does not exist: " + appPropertiesFile);
		}

		try (InputStream in = appPropertiesFile.getInputStream()) {
			load(in);
		}
	}

	/**
	 * Creates a new application properties from the application properties files found
	 * in the given application root directories.  If multiple application properties files
	 * are found, the properties from the files will be combined.  If duplicate keys exist,
	 * the newest key encountered will overwrite the existing key.
	 * 
	 * @param applicationRootDirs The application root directories to look for the properties files in.
	 * @throws IOException If there was a problem loading/reading a discovered properties file.
	 */
	public ApplicationProperties(Collection<ResourceFile> applicationRootDirs) throws IOException {
		boolean found = false;
		for (ResourceFile appRoot : applicationRootDirs) {
			ResourceFile appPropertiesFile = new ResourceFile(appRoot, PROPERTY_FILE);
			if (appPropertiesFile.exists()) {
				try (InputStream in = appPropertiesFile.getInputStream()) {
					load(in);
					found = true;
				}
			}
		}
		if (!found) {
			throw new IOException(PROPERTY_FILE + " was not found!");
		}
	}

	/**
	 * Gets the given application property.  Note that if the specified property is defined
	 * as a system property, the system property will be given precedence and returned.
	 * 
	 * @param propertyName The property name to get.
	 * @return The property.
	 */
	@Override
	public String getProperty(String propertyName) {
		String value = System.getProperty(propertyName);
		if (value != null) {
			return value;
		}
		return super.getProperty(propertyName);
	}

	/**
	 * Gets the application's name.
	 * 
	 * @return The application's name (empty string if undefined).
	 */
	public String getApplicationName() {
		String appName = getProperty(ApplicationProperties.APPLICATION_NAME_PROPERTY);
		if (appName == null || appName.trim().isEmpty()) {
			return "";
		}
		return appName;
	}

	/**
	 * Gets the application's version.
	 * 
	 * @return The application's version (empty string if undefined).
	 */
	public String getApplicationVersion() {
		String appVersion = getProperty(ApplicationProperties.APPLICATION_VERSION_PROPERTY);
		if (appVersion == null || appVersion.trim().isEmpty()) {
			return "";
		}
		return appVersion;
	}

	/**
	 * Gets the application's release name.
	 * 
	 * @return The application's release name (empty string if undefined).
	 */
	public String getApplicationReleaseName() {
		String appReleaseName = getProperty(ApplicationProperties.RELEASE_NAME_PROPERTY);
		if (appReleaseName == null || appReleaseName.trim().isEmpty()) {
			return "";
		}
		return appReleaseName;
	}

	/**
	 * Gets the application's build date.
	 * 
	 * @return The application's build date.
	 */
	public String getApplicationBuildDate() {
		String appBuildDate = getProperty(ApplicationProperties.BUILD_DATE_PROPERTY);
		if (appBuildDate == null || appBuildDate.trim().isEmpty()) {
			// Use today if property is not defined
			appBuildDate = new SimpleDateFormat("yyyy-MMM-dd").format(new Date());
		}
		return appBuildDate;
	}
}
