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
package ghidra.app.util.headless;

import java.io.*;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.*;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.DomainObjectAdapter;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;
import utility.application.ApplicationLayout;

/**
 * A simple class for running scripts outside of Ghidra.
 */
public class GhidraScriptRunner implements GhidraLaunchable {

	private List<String> scriptPaths;
	private String propertiesFilePath;

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {

		if (args.length != 1) {
			usage();
			System.exit(0);
		}
		String logFile = null; //TODO get from arguments?
		GhidraScriptUtil.initialize(new BundleHost(), scriptPaths);
		try {
			initialize(layout, logFile, true);
			runScript(args[0]);
		}
		finally {
			GhidraScriptUtil.dispose();
		}
	}

	private void runScript(String string) throws Exception {
		GhidraScript ghidraScript = getGhidraScript(string);
		GhidraState scriptState = new GhidraState(null, null, null, null, null, null);
		runScript(scriptState, ghidraScript);
	}

	/**
	 * Runs the specified script with the specified state.
	 * 
	 * @param scriptState  State representing environment variables that the script is able
	 * 		to access.
	 * @param script  Script to be run.
	 * @return  whether the script successfully completed running
	 */
	private boolean runScript(GhidraState scriptState, GhidraScript script) {
		ResourceFile srcFile = script.getSourceFile();
		String scriptName =
			srcFile != null ? srcFile.getAbsolutePath() : (script.getClass().getName() + ".class");

		try {
			PrintWriter writer = new PrintWriter(System.out);
			Msg.info(this, "SCRIPT: " + scriptName);
			script.execute(scriptState, TaskMonitor.DUMMY, writer);
			writer.flush();
		}
		catch (Exception exc) {
			Program prog = scriptState.getCurrentProgram();
			String path = (prog != null ? prog.getExecutablePath() : "Current program is null.");
			String logErrorMsg =
				path + "\nREPORT SCRIPT ERROR: " + scriptName + " : " + exc.getMessage();
			Msg.error(this, logErrorMsg, exc);
			return false;
		}

		return true;
	}

	private static void usage() {
		System.out.println("usage: GhidraScriptRunner <scriptName>.java");
	}

	private GhidraScript getGhidraScript(String scriptName) throws Exception {
		ResourceFile scriptSourceFile = findScriptSourceFile(scriptName);
		GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptSourceFile);

		if (provider == null) {
			throw new IOException("Missing plugin needed to run scripts of this type. Please " +
				"ensure you have installed the necessary plugin.");
		}

		PrintWriter writer = new PrintWriter(System.out);
		GhidraScript foundScript = provider.getScriptInstance(scriptSourceFile, writer);

		if (propertiesFilePath != null) {
			// Get basename, assume that it ends in .java, since we've already covered the
			// .class case
			String baseScriptName = foundScript.getScriptName();
			int lastIndexOf = baseScriptName.lastIndexOf(".");
			if (lastIndexOf > 0) {
				baseScriptName = baseScriptName.substring(0, lastIndexOf);
			}
			foundScript.setPropertiesFileLocation(propertiesFilePath, baseScriptName);
		}

		return foundScript;
	}

	private ResourceFile findScriptSourceFile(String scriptName) {
		if (scriptName.endsWith(".class")) {
			scriptName = scriptName.replace(".class", ".java");
		}
		ResourceFile scriptSource = new ResourceFile(scriptName);
		scriptSource = scriptSource.getCanonicalFile();
		if (scriptSource.exists()) {
			return scriptSource;
		}

		scriptSource = GhidraScriptUtil.findScriptByName(scriptName);
		if (scriptSource != null) {
			return scriptSource;
		}
		throw new IllegalArgumentException("Script not found: " + scriptName);
	}

	private synchronized void initialize(ApplicationLayout applicationLayout, String logFile,
			boolean useLog4j) {
		/**
		 * Ensure that we are running in "headless mode"
		 */
		System.setProperty(SystemUtilities.HEADLESS_PROPERTY, Boolean.TRUE.toString());

		// Set this property to prevent static Swing-based methods from running (causes headless
		// operation to lose focus)
		System.setProperty("java.awt.headless", "true");

		/**
		 * Initialize Ghidra Runtime Environment
		 */
		initializeApplication(applicationLayout, logFile, useLog4j);

		// Allows handling of old content which did not have a content type property
		DomainObjectAdapter.setDefaultContentClass(ProgramDB.class);

		initializeScriptPaths();
	}

	protected synchronized void initializeApplication(ApplicationLayout applicationLayout,
			String logFile, boolean useLog4j) {
		HeadlessGhidraApplicationConfiguration configuration =
			new HeadlessGhidraApplicationConfiguration();

		if (useLog4j) {
			if (logFile != null) {
				// configure log4j log file
				configuration.setApplicationLogFile(new File(logFile));
			}

//			if (scriptLogFile != null) {
//				configuration.setScriptLogFile(new File(scriptLogFile));
//			}
		}
		else {
			// use our own file logger when log4j use is disabled
			HeadlessErrorLogger fileErrorLogger = new HeadlessErrorLogger(new File(logFile));
			configuration.setInitializeLogging(false);
			Msg.setErrorLogger(fileErrorLogger);
		}

		Application.initializeApplication(applicationLayout, configuration);
	}

	/**
	 * Gather paths where scripts may be found.
	 */
	private void initializeScriptPaths() {
		StringBuffer buf = new StringBuffer("HEADLESS Script Paths:");
		for (ResourceFile dir : GhidraScriptUtil.getScriptSourceDirectories()) {
			buf.append("\n    ");
			buf.append(dir.getAbsolutePath());
		}
		Msg.info(HeadlessAnalyzer.class, buf.toString());
	}

}
