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
package ghidra.app.plugin.core.vscode;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import org.apache.commons.io.*;

import com.google.gson.*;

import docking.DockingWindowManager;
import docking.action.builder.ActionBuilder;
import docking.options.OptionsService;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.values.ValuesMapDialog;
import generic.theme.GIcon;
import ghidra.*;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.VSCodeIntegrationService;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.framework.Application;
import ghidra.framework.ApplicationProperties;
import ghidra.framework.main.AppInfo;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.*;
import ghidra.util.task.TaskLauncher;
import utilities.util.FileUtilities;

/**
 * {@link Plugin} responsible integrating Ghidra with Visual Studio Code
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Visual Studio Code Integration",
	description = "Allows Ghidra to integrate with Visual Studio Code.",
	servicesRequired = { OptionsService.class },
	servicesProvided = { VSCodeIntegrationService.class }
)
//@formatter:on
public class VSCodeIntegrationPlugin extends ProgramPlugin implements VSCodeIntegrationService {

	private ToolOptions options;
	private Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

	/**
	 * Create a new {@link VSCodeIntegrationPlugin}
	 * 
	 * @param tool The associated {@link PluginTool tool}
	 */
	public VSCodeIntegrationPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	public void init() {
		super.init();

		options = AppInfo.getFrontEndTool().getOptions(
			VSCodeIntegrationOptionsPlugin.PLUGIN_OPTIONS_NAME);

		new ActionBuilder("CreateVSCodeModuleProject", name)
				.menuPath(ToolConstants.MENU_TOOLS, "Create VSCode Module Project...")
				.menuIcon(new GIcon("icon.plugin.scriptmanager.edit.vscode"))
				.description("Creates a new Visual Studio Code module project.")
				.helpLocation(new HelpLocation("VSCodeIntegration", "VSCodeModuleProject"))
				.onAction(context -> showNewProjectDialog())
				.buildAndInstall(tool);
	}

	/**
	 * Present the user with a dialog that allows them to select a name and location for their new
	 * Visual Studio Code Module Project
	 */
	private void showNewProjectDialog() {
		if (!SystemUtilities.isInReleaseMode()) {
			Msg.showInfo(this, tool.getToolFrame(), name,
				"This action may only run from a built Ghidra release.");
			return;
		}

		final String PROJECT_NAME_PROMPT = "Project name";
		final String PROJECT_ROOT_PROMPT = "Project root directory";

		GhidraValuesMap values = new GhidraValuesMap();
		values.defineString(PROJECT_NAME_PROMPT);
		values.defineDirectory(PROJECT_ROOT_PROMPT, new File(System.getProperty("user.home")));
		ValuesMapDialog dialog =
			new ValuesMapDialog("Create New Visual Studio Code Module Project", null, values);
		DockingWindowManager.showDialog(dialog);
		if (dialog.isCancelled()) {
			return;
		}
		values = (GhidraValuesMap) dialog.getValues();

		String projectName = values.getString(PROJECT_NAME_PROMPT);
		File projectRootDir = values.getFile(PROJECT_ROOT_PROMPT);
		File projectDir = new File(projectRootDir, projectName);
		if (projectDir.exists()) {
			Msg.showError(this, tool.getToolFrame(), name,
				"Directory '%s' already exists...exiting".formatted(projectDir));
			return;
		}

		try {
			createVSCodeModuleProject(projectDir);
			Msg.showInfo(this, tool.getToolFrame(), name,
				"Successfully created Visual Studio Code module project directory at: " +
					projectDir);
		}
		catch (IOException e) {
			Msg.showError(this, tool.getToolFrame(), name,
				"Failed to create Visual Studio Code module project directory at: " + projectDir,
				e);
		}
	}

	@Override
	public ToolOptions getVSCodeIntegrationOptions() {
		return options;
	}

	@Override
	public File getVSCodeExecutableFile() throws FileNotFoundException {
		File vscodeExecutableFile =
			options.getFile(VSCodeIntegrationOptionsPlugin.VSCODE_EXE_PATH_OPTION, null);
		if (vscodeExecutableFile == null || !vscodeExecutableFile.isFile()) {
			throw new FileNotFoundException(
				"Visual Studio Code installation executable file does not exist.");
		}
		return vscodeExecutableFile;
	}

	@Override
	public void launchVSCode(File file) {
		TaskLauncher.launch(new VSCodeLauncherTask(this, file));
	}

	@Override
	public void handleVSCodeError(String error, boolean askAboutOptions, Throwable t) {
		if (askAboutOptions && !SystemUtilities.isInHeadlessMode()) {
			SystemUtilities.runSwingNow(() -> {
				int choice =
					OptionDialog.showYesNoDialog(null, "Failed to launch Visual Studio Code",
						error + "\nWould you like to verify your \"" +
							VSCodeIntegrationOptionsPlugin.PLUGIN_OPTIONS_NAME +
							"\" options now?");
				if (choice == OptionDialog.YES_OPTION) {
					AppInfo.getFrontEndTool()
							.getService(OptionsService.class)
							.showOptionsDialog(
								VSCodeIntegrationOptionsPlugin.PLUGIN_OPTIONS_NAME, null);
				}
			});
		}
		else {
			Msg.showError(VSCodeIntegrationPlugin.class, null,
				"Failed to launch Visual Studio Code", error, t);
		}
	}

	@Override
	public void createVSCodeModuleProject(File projectDir) throws IOException {

		File installDir = Application.getInstallationDirectory().getFile(false);
		Map<String, String> classpathSourceMap = getClasspathSourceMap();

		JsonObject settings = createSettings(installDir, projectDir, classpathSourceMap,
			List.of("src/main/java", "ghidra_scripts"), "bin/main");
		JsonObject launch =
			createLaunch(installDir, projectDir, classpathSourceMap, "${workspaceFolder}");

		File vscodeDir = new File(projectDir, ".vscode");
		if (!FileUtilities.mkdirs(vscodeDir)) {
			throw new IOException("Failed to create: " + vscodeDir);
		}
		File settingsFile = new File(vscodeDir, "settings.json");
		File launchFile = new File(vscodeDir, "launch.json");
		FileUtils.writeStringToFile(settingsFile, gson.toJson(settings), StandardCharsets.UTF_8);
		FileUtils.writeStringToFile(launchFile, gson.toJson(launch), StandardCharsets.UTF_8);

		writeSampleScriptJava(projectDir);
		writeSampleScriptPyGhidra(projectDir);
		writeSampleModule(installDir, projectDir);
	}

	@Override
	public void addToVSCodeWorkspace(File workspaceFile, File projectDir) throws IOException {

		File installDir = Application.getInstallationDirectory().getFile(false);
		Map<String, String> classpathSourceMap = getClasspathSourceMap();
		JsonObject settings =
			createSettings(installDir, projectDir, classpathSourceMap, List.of("."), null);
		JsonObject launch = createLaunch(installDir, projectDir, classpathSourceMap, null);
		
		JsonObject workspace;
		if (workspaceFile.isFile()) {
			String str = FileUtils.readFileToString(workspaceFile, StandardCharsets.UTF_8);
			JsonElement element = JsonParser.parseString(str);
			if (!(element instanceof JsonObject json)) {
				throw new IOException("'%s' was not a JsonObject".formatted(workspaceFile));
			}
			workspace = addToExistingWorkspace(projectDir, json, settings, launch);
		}
		else {
			workspace = addToExistingWorkspace(projectDir, createNewWorkspace(settings, launch),
				settings, launch);
		}

		if (!FileUtilities.mkdirs(workspaceFile.getParentFile())) {
			throw new IOException("Failed to create: " + workspaceFile.getParentFile());
		}
		FileUtils.writeStringToFile(workspaceFile, gson.toJson(workspace), StandardCharsets.UTF_8);
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
	 * Creates the VSCode settings json
	 * 
	 * @param installDir The Ghidra installation directory
	 * @param projectDir The VSCode project directory
	 * @param classpathSourceMap The classpath/source map (see {@link #getClasspathSourceMap()})
	 * @param sourcePaths A {@link List} of source paths
	 * @param outputPath The output path (null for default)
	 * @return The VSCode settings json
	 * @throws IOException if an IO-related error occurs
	 */
	private JsonObject createSettings(File installDir, File projectDir,
			Map<String, String> classpathSourceMap, List<String> sourcePaths, String outputPath)
			throws IOException {
		String gradleVersion = Application
				.getApplicationProperty(ApplicationProperties.APPLICATION_GRADLE_MIN_PROPERTY);

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
		sourcePaths.forEach(sourcePathArray::add);

		if (outputPath != null) {
			json.addProperty("java.project.outputPath", outputPath);
		}

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

		return json;
	}

	/**
	 * Creates the VSCode launch json
	 * 
	 * @param installDir The Ghidra installation directory
	 * @param projectDir The VSCode project directory
	 * @param classpathSourceMap The classpath/source map (see {@link #getClasspathSourceMap()})
	 * @param externalModules The Ghidra external modules to pass to Ghidra (could be null)
	 * @return The VSCode launch json
	 * @throws IOException if an IO-related error occurs
	 */
	private JsonObject createLaunch(File installDir, File projectDir,
			Map<String, String> classpathSourceMap, String externalModules) throws IOException {

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
		if (externalModules != null) {
			vmArgsArray.add("-Dghidra.external.modules=" + externalModules);
		}
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

		// Ghidra Attach
		JsonObject ghidraAttachObject = new JsonObject();
		configurationsArray.add(ghidraAttachObject);
		ghidraAttachObject.addProperty("type", "java");
		ghidraAttachObject.addProperty("name", "Ghidra Attach");
		ghidraAttachObject.addProperty("request", "attach");
		ghidraAttachObject.addProperty("hostName", "localhost");
		ghidraAttachObject.addProperty("port", 18001);
		
		return json;
	}

	/**
	 * Creates a new VSCode workspace with no folders added
	 * 
	 * @param settings The VSCode settings JSON
	 * @param launch The VSCode launch JSON
	 * @return The new workspace JSON
	 */
	private JsonObject createNewWorkspace(JsonObject settings, JsonObject launch) {
		JsonObject json = new JsonObject();
		JsonArray foldersArray = new JsonArray();
		json.add("folders", foldersArray);
		JsonObject folderObject = new JsonObject();
		foldersArray.add(folderObject);
		json.add("settings", settings);
		json.add("launch", launch);

		return json;
	}

	/**
	 * Adds the given project directory to the given workspace
	 * 
	 * @param projectDir The VSCode project directory to add
	 * @param workspace The VSCode workspace to add to
	 * @param settings The VSCode settings JSON
	 * @param launch The VSCode launch JSON
	 * @return The new workspace JSON with the project added
	 */
	private JsonObject addToExistingWorkspace(File projectDir, JsonObject workspace, JsonObject settings,
			JsonObject launch) {
		File projectParentDir = projectDir.getParentFile();
		String folderName = projectDir.getName();
		if (projectParentDir != null) {
			folderName = projectParentDir.getName() + "/" + folderName;
		}

		JsonArray foldersArray = workspace.getAsJsonArray("folders");
		JsonObject folderObject = new JsonObject();
		folderObject.addProperty("name",
			projectDir.getParentFile().getName() + "/" + projectDir.getName());
		folderObject.addProperty("path", projectDir.getAbsolutePath());
		if (!foldersArray.contains(folderObject)) {
			foldersArray.add(folderObject);
		}
		return workspace;
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
			String oldName = f.getName();
			if (!oldName.startsWith(skeleton)) {
				continue;
			}
			String newName = projectName + oldName.substring(skeleton.length(), oldName.length());
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
