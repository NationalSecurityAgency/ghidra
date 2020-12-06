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

import java.io.File;
import java.net.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;

public class LoggingInitialization {

	private static final String LOG4J_CONFIGURATION_PROPERTY = "log4j.configuration";
	private static final String LOG4J2_CONFIGURATION_PROPERTY = "log4j.configurationFile";

	private static final String PRODUCTION_LOGGING_CONFIGURATION_FILE = "generic.log4j.xml";
	private static final String DEVELOPMENT_LOGGING_CONFIGURATION_FILE = "generic.log4jdev.xml";

	private static boolean INITIALIZED = false;
	private static File SCRIPT_LOG_FILE = null;
	private static File APPLICATION_LOG_FILE = null;

	public synchronized static void initializeLoggingSystem() {

		if (INITIALIZED) {
			return;
		}

		URL resource = getLoggingConfigFileUrl();
		if (resource != null) {
			try {
				LoggerContext context = (LoggerContext) LogManager.getContext(false);
				context.setConfigLocation(resource.toURI());

				// make future, unresolved contexts (e.g. from OSGi bundles) use this configuration
				System.setProperty(LOG4J2_CONFIGURATION_PROPERTY, resource.toURI().toString());
			}
			catch (URISyntaxException e) {
				Msg.error(LoggingInitialization.class, "Unable to convert URL to URI", e);
			}
		}

		Msg.setErrorLogger(new Log4jErrorLogger());
		String configFilename =
			(resource == null) ? "<no config file found>" : resource.toExternalForm();
		Msg.info(LoggingInitialization.class, "Using log config file: " + configFilename);
		Msg.info(LoggingInitialization.class, "Using log file: " + APPLICATION_LOG_FILE);
		INITIALIZED = true;
	}

	private static URL getLoggingConfigFileUrl() {
		URL resource = getLogFileFromSystemProperty();
		if (resource != null) {
			return resource;
		}

		// no system property resource defined...use one of our defaults
		String loggingConfigFilename = PRODUCTION_LOGGING_CONFIGURATION_FILE;
		if (SystemUtilities.isInDevelopmentMode()) {
			loggingConfigFilename = DEVELOPMENT_LOGGING_CONFIGURATION_FILE;
		}

		return ResourceManager.getResource(loggingConfigFilename);
	}

	private static URL getLogFileFromSystemProperty() {
		String configString = System.getProperty(LOG4J_CONFIGURATION_PROPERTY);
		if (configString == null) {
			return null;
		}

		// first see if the given filename is something that is in our classpath
		URL resource = ResourceManager.getResource(configString);
		if (resource != null) {
			return resource;
		}

		File configFile = new File(configString);
		if (!configFile.exists()) {
			// maybe it is already in URL form: file://some/file/path
			try {
				URL url = new URL(configString);

				File file = new File(url.toURI());
				if (file.exists()) {
					return url;
				}
			}
			catch (Exception e) {
				// handled below
			}

			// we have to reset the property so that the DOMConfigurator does not use it
			System.setProperty(LOG4J_CONFIGURATION_PROPERTY, "");
			System.err.println("Log config file does not exist: " + configString);
			return null;
		}

		URI URI = configFile.toURI();
		try {
			return URI.toURL();
		}
		catch (MalformedURLException e) {
			// not sure if this can happen, since we validated that the file already exists
			System.err.println("Unable to find requested log configuration file: " + configString);
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Returns the default file used for logging messages.
	 */
	public synchronized static File getApplicationLogFile() {
		if (APPLICATION_LOG_FILE == null) {
			throw new AssertException(
				"Before logging system is used you must call Application.initializeApplication() " +
					"AND its application configuration's setInitializeLogging() must NOT be " +
					"set to false.");
		}
		return APPLICATION_LOG_FILE;
	}

	/**
	 * Use this to override the default application log file, before you
	 * initialize the logging system.
	 * 
	 * @param file The file to use as the application log file
	 */
	synchronized static void setApplicationLogFile(File file) {
		if (APPLICATION_LOG_FILE != null && !SystemUtilities.isInTestingMode()) {
			// don't throw the exception so that we may can continue to work
			System.err.println("Cannot change the log file once it has been " +
				"initialized!\nYou must call this method before calling " +
				"LoggingInitialization.initializeLoggingSystem()");
			(new IllegalStateException()).printStackTrace();
		}
		APPLICATION_LOG_FILE = file;

		// Need to set the system property that the log4j2 configuration reads in
		// order to determine the log file name. Once that's set, the log 
		// configuration must be 'kicked' to pick up the change.
		System.setProperty("logFilename", file.getAbsolutePath());
		if (INITIALIZED) {
			((LoggerContext) LogManager.getContext(false)).reconfigure();
		}
	}

	/**
	 * Returns the default file used for logging messages.
	 */
	public synchronized static File getScriptLogFile() {
		if (SCRIPT_LOG_FILE == null) {
			throw new AssertException(
				"Must call Application.initializeApplication before logging system is used");
		}
		return SCRIPT_LOG_FILE;
	}

	/**
	 * Use this to override the default application log file, before you
	 * initialize the logging system.
	 * 
	 * @param file The file to use as the application log file
	 */
	synchronized static void setScriptLogFile(File file) {
		if (SCRIPT_LOG_FILE != null && !SystemUtilities.isInTestingMode()) {
			// don't throw the exception so that we may can continue to work
			System.err.println("Cannot change the log file once it has been " +
				"initialized!\nYou must call this method before calling " +
				"LoggingInitialization.initializeLoggingSystem()");
			(new IllegalStateException()).printStackTrace();
		}
		SCRIPT_LOG_FILE = file;

		// Need to set the system property that the log4j2 configuration reads in
		// order to determine the script log file name. Once that's set, the log 
		// configuration must be 'kicked' to pick up the change.
		System.setProperty("scriptLogFilename", file.getAbsolutePath());

		if (INITIALIZED) {
			((LoggerContext) LogManager.getContext(false)).reconfigure();
		}
	}
}
