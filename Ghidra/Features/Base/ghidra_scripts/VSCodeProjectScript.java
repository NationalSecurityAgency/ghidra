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
// Creates a new VSCode project for Ghidra script and module development.
// @category Development

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import org.apache.commons.io.*;

import com.google.gson.*;

import ghidra.*;
import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.framework.Application;
import ghidra.framework.ApplicationProperties;
import ghidra.util.SystemUtilities;
import utilities.util.FileUtilities;

public class VSCodeProjectScript extends GhidraScript {

	private Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

	@Override
	protected void run() throws Exception {
		if (!SystemUtilities.isInReleaseMode()) {
			printerr("This script may only run from a built Ghidra release.");
			return;
		}

		final String PROJECT_NAME_PROMPT = "Project name";
		final String PROJECT_ROOT_PROMPT = "Project root directory";

		GhidraValuesMap values = new GhidraValuesMap();
		values.defineString(PROJECT_NAME_PROMPT);
		values.defineDirectory(PROJECT_ROOT_PROMPT, new File(System.getProperty("user.home")));
		values = askValues("Setup New VSCode Project", null, values);

		String projectName = values.getString(PROJECT_NAME_PROMPT);
		File projectRootDir = values.getFile(PROJECT_ROOT_PROMPT);
		File projectDir = new File(projectRootDir, projectName);
		if (projectDir.exists()) {
			printerr("Directory '%s' already exists...exiting".formatted(projectDir));
			return;
		}

		File installDir = Application.getInstallationDirectory().getFile(false);
		Map<String, String> classpathSourceMap = getClasspathSourceMap();
		writeSettings(installDir, projectDir, classpathSourceMap);
		writeLaunch(installDir, projectDir, classpathSourceMap);
		writeSampleScriptJava(projectDir);
		writeSampleScriptPyGhidra(projectDir);
		writeSampleModule(installDir, projectDir);

		println("Successfully created VSCode project directory at: " + projectDir);
		println(
			"To debug, please close Ghidra and relaunch from the VSCode Ghidra launch configuration.");
	}

	/**
	 * Gets the classpath and source of the currently running Ghidra
	 * 
	 * @return A {@link Map} of classpath jars to their corresponding source zip files (source zip
	 *   could be null if it doesn't exist)
	 * @throws IOException if an IO-related error occurs
	 */
	private Map<String, String> getClasspathSourceMap() throws IOException {
		Map<String, String> classpathSourceMap = new LinkedHashMap<>();
		for (String entry : GhidraClassLoader.getClasspath(GhidraClassLoader.CP)) {
			entry = new File(entry).getCanonicalPath();
			String sourcePath = entry.substring(0, entry.length() - 4) + "-src.zip";
			if (!entry.endsWith(".jar") || !new File(sourcePath).exists()) {
				sourcePath = null;
			}
			classpathSourceMap.put(entry, sourcePath);
		}
		return classpathSourceMap;
	}

	/**
	 * Write the .vscode/settings.json file
	 * 
	 * @param installDir The Ghidra installation directory
	 * @param projectDir The VSCode project directory
	 * @param classpathSourceMap The classpath/source map (see {@link #getClasspathSourceMap()})
	 * @throws IOException if an IO-related error occurs
	 */
	private void writeSettings(File installDir, File projectDir,
			Map<String, String> classpathSourceMap) throws IOException {
		File vscodeDir = new File(projectDir, ".vscode");
		File settingsFile = new File(vscodeDir, "settings.json");
		String gradleVersion = Application
				.getApplicationProperty(ApplicationProperties.APPLICATION_GRADLE_MIN_PROPERTY);
		String pythonInterpreterPath = System.getProperty("pyghidra.sys.prefix", null);
		
		// Build settings json object
		JsonObject json = new JsonObject();
		json.addProperty("java.import.maven.enabled", false);
		json.addProperty("java.import.gradle.enabled", false);
		json.addProperty("java.import.gradle.wrapper.enabled", false);
		json.addProperty("java.import.gradle.version", gradleVersion);
		json.addProperty("java.format.settings.url",
			new File(installDir, "support/eclipse/GhidraEclipseFormatter.xml").getAbsolutePath());

		JsonArray sourcePathArray = new JsonArray();
		json.add("java.project.sourcePaths", sourcePathArray);
		sourcePathArray.add("src/main/java");
		sourcePathArray.add("ghidra_scripts");

		json.addProperty("java.project.outputPath", "bin/main");
		JsonObject referencedLibrariesObject = new JsonObject();

		json.add("java.project.referencedLibraries", referencedLibrariesObject);
		JsonArray includeArray = new JsonArray();
		referencedLibrariesObject.add("include", includeArray);
		classpathSourceMap.keySet().forEach(includeArray::add);
		JsonObject sourcesObject = new JsonObject();
		referencedLibrariesObject.add("sources", sourcesObject);
		classpathSourceMap.entrySet()
				.stream()
				.filter(e -> e.getValue() != null)
				.forEach(e -> sourcesObject.addProperty(e.getKey(), e.getValue()));

		json.addProperty("python.analysis.stubPath",
			new File(installDir, "docs/ghidra_stubs/typestubs").getAbsolutePath());
		if (pythonInterpreterPath != null) {
			json.addProperty("python.defaultInterpreterPath", pythonInterpreterPath);
		}

		// Write settings json object
		if (!FileUtilities.mkdirs(settingsFile.getParentFile())) {
			throw new IOException("Failed to create: " + settingsFile.getParentFile());
		}
		FileUtils.writeStringToFile(settingsFile, gson.toJson(json), StandardCharsets.UTF_8);
	}

	/**
	 * Write the .vscode/launch.json file
	 * 
	 * @param installDir The Ghidra installation directory
	 * @param projectDir The VSCode project directory
	 * @param classpathSourceMap The classpath/source map (see {@link #getClasspathSourceMap()})
	 * @throws IOException if an IO-related error occurs
	 */
	private void writeLaunch(File installDir, File projectDir,
			Map<String, String> classpathSourceMap) throws IOException {
		File vscodeDir = new File(projectDir, ".vscode");
		File launchFile = new File(vscodeDir, "launch.json");

		// Get the path of Utility.jar so we can put it on the classpath
		String utilityJarPath = classpathSourceMap.keySet()
				.stream()
				.filter(e -> e.endsWith("Utility.jar"))
				.findFirst()
				.orElseThrow();

		// Get JVM args from launch.properties by calling LaunchSupport
		List<String> args = new ArrayList<>();
		args.add(System.getProperty("java.home") + "/bin/java");
		args.add("-cp");
		args.add(new File(installDir, "support/LaunchSupport.jar").getPath());
		args.add("LaunchSupport");
		args.add(installDir.getPath());
		args.add("-vmArgs");
		ProcessBuilder pb = new ProcessBuilder(args);
		Process p = pb.start();
		List<String> vmArgs = IOUtils.readLines(p.getInputStream(), StandardCharsets.UTF_8);

		// Build launch json object
		JsonObject json = new JsonObject();
		json.addProperty("version", "0.2.0");
		JsonArray configurationsArray = new JsonArray();
		json.add("configurations", configurationsArray);

		// Ghidra launcher
		JsonObject ghidraConfigObject = new JsonObject();
		configurationsArray.add(ghidraConfigObject);
		ghidraConfigObject.addProperty("type", "java");
		ghidraConfigObject.addProperty("name", "Ghidra");
		ghidraConfigObject.addProperty("request", "launch");
		ghidraConfigObject.addProperty("mainClass", Ghidra.class.getName());
		ghidraConfigObject.addProperty("args", GhidraRun.class.getName());
		JsonArray classPathsArray = new JsonArray();
		ghidraConfigObject.add("classPaths", classPathsArray);
		classPathsArray.add(utilityJarPath);
		JsonArray vmArgsArray = new JsonArray();
		ghidraConfigObject.add("vmArgs", vmArgsArray);
		vmArgsArray.add("-Dghidra.external.modules=${workspaceFolder}");
		vmArgs.forEach(vmArgsArray::add);

		// PyGhidra launcher
		JsonObject pyghidraConfigObject = new JsonObject();
		configurationsArray.add(pyghidraConfigObject);
		pyghidraConfigObject.addProperty("type", "debugpy");
		pyghidraConfigObject.addProperty("name", "PyGhidra");
		pyghidraConfigObject.addProperty("request", "launch");
		pyghidraConfigObject.addProperty("module", "pyghidra.ghidra_launch");
		pyghidraConfigObject.addProperty("args", GhidraRun.class.getName());
		JsonArray argsArray = new JsonArray();
		pyghidraConfigObject.add("args", argsArray);
		argsArray.add("--install-dir");
		argsArray.add(installDir.getAbsolutePath());
		argsArray.add("-g");
		argsArray.add(GhidraRun.class.getName());
		JsonObject envObject = new JsonObject();
		pyghidraConfigObject.add("env", envObject);
		envObject.addProperty("PYGHIDRA_DEBUG", "1");

		// PyGhidra Java Attach
		JsonObject pyghidraAttachObject = new JsonObject();
		configurationsArray.add(pyghidraAttachObject);
		pyghidraAttachObject.addProperty("type", "java");
		pyghidraAttachObject.addProperty("name", "PyGhidra Java Attach");
		pyghidraAttachObject.addProperty("request", "attach");
		pyghidraAttachObject.addProperty("hostName", "localhost");
		pyghidraAttachObject.addProperty("port", 18001);

		// Write launch json object
		if (!FileUtilities.mkdirs(launchFile.getParentFile())) {
			throw new IOException("Failed to create: " + launchFile.getParentFile());
		}
		FileUtils.writeStringToFile(launchFile, gson.toJson(json), StandardCharsets.UTF_8);
	}

	/**
	 * Write a sample Java-based GhidraScript into the VSCode project directory
	 * 
	 * @param projectDir The VSCode project directory
	 * @throws IOException if an IO-related error occurs
	 */
	private void writeSampleScriptJava(File projectDir) throws IOException {
		File scriptsDir = new File(projectDir, "ghidra_scripts");
		File scriptFile = new File(scriptsDir, "SampleScript.java");
		String sampleScript = """
				// Sample Java GhidraScript
				// @category Examples
				import ghidra.app.script.GhidraScript;

				public class SampleScript extends GhidraScript {

					@Override
					protected void run() throws Exception {
				    	println(\"Sample script!\");
					}
				}
				""";
		if (!FileUtilities.mkdirs(scriptFile.getParentFile())) {
			throw new IOException("Failed to create: " + scriptFile.getParentFile());
		}
		FileUtils.writeStringToFile(scriptFile, sampleScript, StandardCharsets.UTF_8);
	}
	
	private void writeSampleScriptPyGhidra(File projectDir) throws IOException {
		File scriptsDir = new File(projectDir, "ghidra_scripts");
		File scriptFile = new File(scriptsDir, "sample_script.py");
		String sampleScript = """
				# Sample PyGhidra GhidraScript
				# @category Examples
				# @runtime PyGhidra

				from java.util import LinkedList
				java_list = LinkedList([1,2,3])

				block = currentProgram.memory.getBlock('.text')
				""";
		if (!FileUtilities.mkdirs(scriptFile.getParentFile())) {
			throw new IOException("Failed to create: " + scriptFile.getParentFile());
		}
		FileUtils.writeStringToFile(scriptFile, sampleScript, StandardCharsets.UTF_8);
	}

	/**
	 * Write a sample Java-based Ghidra module into the VSCode project directory
	 * 
	 * @param installDir The Ghidra installation directory
	 * @param projectDir The VSCode project directory
	 * @throws IOException if an IO-related error occurs
	 */
	private void writeSampleModule(File installDir, File projectDir) throws IOException {
		// Copy Skeleton and rename module
		String skeleton = "Skeleton";
		File skeletonDir = new File(installDir, "Extensions/Ghidra/Skeleton");
		FileUtils.copyDirectory(skeletonDir, projectDir);

		// Rename package
		String projectName = projectDir.getName();
		File srcDir = new File(projectDir, "src/main/java");
		File oldPackageDir = new File(srcDir, skeleton.toLowerCase());
		File newPackageDir = new File(srcDir, projectName.toLowerCase());
		if (!oldPackageDir.renameTo(newPackageDir)) {
			throw new IOException("Failed to rename: " + oldPackageDir);
		}

		// Rename java files and text replace their contents
		for (File f : newPackageDir.listFiles()) {
			String name = f.getName();
			if (!name.startsWith(skeleton)) {
				continue;
			}
			String newName = projectName + name.substring(skeleton.length(), name.length());
			File newFile = new File(f.getParentFile(), newName);
			if (!f.renameTo(newFile)) {
				throw new IOException("Failed to rename: " + f);
			}
			String fileData = FileUtils.readFileToString(newFile, StandardCharsets.UTF_8);
			fileData = fileData.replaceAll(skeleton, projectName);
			fileData = fileData.replaceAll(skeleton.toLowerCase(), projectName.toLowerCase());
			fileData = fileData.replaceAll(skeleton.toUpperCase(), projectName.toUpperCase());
			FileUtils.writeStringToFile(newFile, fileData, StandardCharsets.UTF_8);
		}

		// Fix Ghidra installation directory path in build.gradle
		File buildTemplateGradleFile = new File(projectDir, "buildTemplate.gradle");
		File buildGradleFile = new File(projectDir, "build.gradle");
		if (!buildTemplateGradleFile.renameTo(buildGradleFile)) {
			throw new IOException("Failed to rename: " + buildTemplateGradleFile);
		}
		String fileData = FileUtils.readFileToString(buildGradleFile, StandardCharsets.UTF_8);
		fileData =
			fileData.replaceAll("<REPLACE>", FilenameUtils.separatorsToUnix(installDir.getPath()));
		FileUtils.writeStringToFile(buildGradleFile, fileData, StandardCharsets.UTF_8);
	}
}
