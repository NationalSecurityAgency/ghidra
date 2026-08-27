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
import java.net.*;
import java.util.List;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.*;
import org.apache.logging.log4j.core.config.xml.XmlConfiguration;

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;

public class LoggingInitialization {

	public static final String LOG4J2_CONFIGURATION_PROPERTY = "log4j.configurationFile";

	private static final String PRODUCTION_LOGGING_CONFIGURATION_FILE = "generic.log4j.xml";
	private static final String DEVELOPMENT_LOGGING_CONFIGURATION_FILE = "generic.log4jdev.xml";

	private static boolean INITIALIZED = false;
	private static File SCRIPT_LOG_FILE = null;
	private static File APPLICATION_LOG_FILE = null;

	public synchronized static void initializeLoggingSystem() {

		if (INITIALIZED) {
			return;
		}

		URL configFileUrl = installConfigFile();

		Msg.setErrorLogger(new Log4jErrorLogger());
		String configFilename =
			(configFileUrl == null) ? "<no config file found>" : configFileUrl.toExternalForm();
		Msg.info(LoggingInitialization.class, "Using log config file: " + configFilename);
		Msg.info(LoggingInitialization.class, "Using log file: " + APPLICATION_LOG_FILE);
		INITIALIZED = true;
	}

	private static URL installConfigFile() {
		URL configFileUrl = getLoggingConfigFileUrl();
		if (configFileUrl == null) {
			return null;
		}

		try {

			// Ensure this property is set. Some code paths set the property, but some do not.
			System.setProperty(LOG4J2_CONFIGURATION_PROPERTY, configFileUrl.toURI().toString());

			// Simply requesting the context will force the log system to initialize.  Make the call
			// so that it will pick up the config file property we just set.
			// Note: this will not work if the log4j was initialized before this call
			LoggerContext ctx = (LoggerContext) LogManager.getContext(false);

			replaceDefaultAppenders(ctx);

			return configFileUrl;
		}
		catch (URISyntaxException e) {
			Msg.error(LoggingInitialization.class, "Unable to convert URL to URI", e);
			return null;
		}
		catch (IOException e) {
			Msg.error(LoggingInitialization.class, "Unable to load file appenders", e);
			return null;
		}
	}

	/**
	 * Our logging system works with a few different config files, one of which is chosen by the
	 * application configuration.  Each config file will use multiple appenders to send log output
	 * to various places: the system console, the UI log display, an application log file and a 
	 * script log file for script messages.  
	 * <P>
	 * Each application, including unit tests, is responsible for making sure that
	 * {@link #initializeLoggingSystem()} is called before clients use any logging. If this call is
	 * not made, and the log4j system gets initialized indirectly, such as through class loading, 
	 * then log4j may create poorly named files in Java's working directory.  To prevent this, we 
	 * have our file appenders default to using the console instead of a file.  When 
	 * {@link #initializeLoggingSystem()} is called, this method will replace those default 
	 * appenders with the desired file appenders. 
	 * 
	 * @param ctx the logging context
	 * @throws IOException if there is a problem reading the appender xml configuration files 
	 */
	private static void replaceDefaultAppenders(LoggerContext ctx) throws IOException {

		ApplicationAppenderPlaceholder applicationAppender = new ApplicationAppenderPlaceholder();
		ScriptAppenderPlaceholder scriptAppender = new ScriptAppenderPlaceholder();

		applicationAppender.install(ctx);
		scriptAppender.install(ctx);

		ctx.updateLoggers(); // Refreshes the context
	}

	private static URL getResource(String relativeName) {
		return LoggingInitialization.class.getClassLoader().getResource(relativeName);
	}

	private static URL getLoggingConfigFileUrl() {
		URL resource = getLogFileFromSystemProperty();
		if (resource != null) {
			return resource;
		}

		// no system property resource defined...use one of our defaults
		return getDefaultLoggingConfigFileUrl();
	}

	private static URL getDefaultLoggingConfigFileUrl() {
		String loggingConfigFilename = PRODUCTION_LOGGING_CONFIGURATION_FILE;
		if (SystemUtilities.isInDevelopmentMode()) {
			loggingConfigFilename = DEVELOPMENT_LOGGING_CONFIGURATION_FILE;
		}

		return getResource(loggingConfigFilename);
	}

	private static URL getLogFileFromSystemProperty() {
		String configString = System.getProperty(LOG4J2_CONFIGURATION_PROPERTY);
		if (configString == null) {
			return null;
		}

		// first see if the given filename is something that is in our classpath
		URL resource = getResource(configString);
		if (resource != null) {
			return resource;
		}

		File configFile = new File(configString);
		if (!configFile.exists()) {
			// maybe it is already in URL form: file://some/file/path
			try {
				URI uri = new URI(configString);
				URL url = uri.toURL();
				File file = new File(uri);
				if (file.exists()) {
					return url;
				}
			}
			catch (Exception e) {
				// handled below
			}

			// we have to reset the property so that the DOMConfigurator does not use it
			System.setProperty(LOG4J2_CONFIGURATION_PROPERTY, "");
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
	 * @return the file
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
	 * Use this to override the default application log file, before you initialize the logging
	 * system.
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

		// Need to set the system property that the log4j2 configuration reads in order to
		// determine the log file name. Once that's set, the log configuration must be 'kicked' to
		// pick up the change.
		System.setProperty("logFilename", file.getAbsolutePath());

		reinitialize();
	}

	/**
	 * Returns the default file used for logging messages.
	 * @return the file
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

		// Need to set the system property that the log4j2 configuration reads in order to
		// determine the script log file name. Once that's set, the log configuration must be
		// 'kicked' to pick up the change.
		System.setProperty("scriptLogFilename", file.getAbsolutePath());

		reinitialize();
	}

	/**
	 * Signals to reload the log settings from the log configuration files in use.  This is useful
	 * for tests that wish to temporarily change log settings, restoring them when done.
	 * <p>
	 * This method will do nothing if {@link #initializeLoggingSystem()} has not been called.
	 */
	public synchronized static void reinitialize() {
		if (INITIALIZED) {
			((LoggerContext) LogManager.getContext(false)).reconfigure();
		}
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	private static class AppenderPlaceholder {

		private String name;
		private String configFilename;
		private Level level;

		AppenderPlaceholder(String name, String configFilename) {
			this.name = name;
			this.configFilename = configFilename;
		}

		void install(LoggerContext ctx) throws IOException {

			if (!loadDefaultAppender(ctx)) {
				return;
			}

			Appender newAppender = createReplacementAppender(ctx);
			replaceAppender(ctx, newAppender);
		}

		private boolean loadDefaultAppender(LoggerContext ctx) {

			Configuration config = ctx.getConfiguration();
			LoggerConfig rootLoggerConfig = config.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);

			List<AppenderRef> refs = rootLoggerConfig.getAppenderRefs();
			for (AppenderRef ref : refs) {
				String appenderName = ref.getRef();
				if (appenderName.equals(name)) {
					level = ref.getLevel();
					return true;
				}
			}

			// Some helpful debug when expected appenders are missing
			if (config instanceof DefaultConfiguration) {
				error("Log4j did not use our config file.  " +
					"Verify it was not initialized before calling LoggingInitialization");
			}

			error("Unable to find '%s' default appender".formatted(name));
			return false;
		}

		private Appender createReplacementAppender(LoggerContext ctx) throws IOException {
			URL url = getResource(configFilename);
			if (url == null) {
				// Logging not initialized; can't use logging
				error("Unable to find appender config '%s'".formatted(configFilename));
				return null;
			}

			try (InputStream fis = url.openStream()) {
				ConfigurationSource source = new ConfigurationSource(fis);
				XmlConfiguration tempConfig = new XmlConfiguration(ctx, source);
				tempConfig.initialize(); // trigger the xml parsing

				Appender appender = tempConfig.getAppender(name);
				if (appender == null) {
					error("Could not find an appender named '%s' in '%s'".formatted(name,
						configFilename));
					return null;
				}
				return appender;
			}
		}

		private void replaceAppender(LoggerContext ctx, Appender newAppender) {
			if (newAppender == null) {
				return; // already printed an error messages before this call
			}

			// remove old appender
			Configuration config = ctx.getConfiguration();
			LoggerConfig rootLoggerConfig = config.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
			rootLoggerConfig.removeAppender(name);

			newAppender.start();
			config.addAppender(newAppender);
			config.getRootLogger().addAppender(newAppender, level, null);
		}

		private void error(String s) {
			// Logging not initialized; can't use logging
			System.err.println(s);
		}
	}

	private static class ApplicationAppenderPlaceholder extends AppenderPlaceholder {
		ApplicationAppenderPlaceholder() {
			super("detail", "log4j-appender-rolling-file.xml");
		}
	}

	private static class ScriptAppenderPlaceholder extends AppenderPlaceholder {
		ScriptAppenderPlaceholder() {
			super("script", "log4j-appender-rolling-file-scripts.xml");
		}
	}
}
