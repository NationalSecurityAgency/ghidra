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
package ghidra.app.plugin.core.eclipse;

import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import docking.widgets.OptionDialog;
import generic.jar.ResourceFile;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.EclipseIntegrationService;
import ghidra.framework.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * Plugin responsible for providing Eclipse-related services to other Ghidra plugins.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Eclipse Integration",
	description = "Allows Ghidra to integrate with Eclipse.",
	servicesRequired = { OptionsService.class },
	servicesProvided = { EclipseIntegrationService.class }
)
//@formatter:on
public class EclipseIntegrationPlugin extends ProgramPlugin implements EclipseIntegrationService {

	private ToolOptions options;

	public EclipseIntegrationPlugin(PluginTool tool) {
		super(tool, true, true, true);
	}

	@Override
	public void init() {
		super.init();
		options = AppInfo.getFrontEndTool().getOptions(
			EclipseIntegrationOptionsPlugin.PLUGIN_OPTIONS_NAME);
	}

	@Override
	public ToolOptions getEclipseIntegrationOptions() {
		return options;
	}

	@Override
	public File getEclipseExecutableFile() throws FileNotFoundException {
		File eclipseInstallDir = getEclipseInstallDir();
		File eclipseExecutableFile;
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.MAC_OS_X) {
			eclipseExecutableFile = new File(eclipseInstallDir.getParentFile(), "MacOS/eclipse");
		}
		else if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
			eclipseExecutableFile = new File(eclipseInstallDir, "eclipse.exe");
		}
		else {
			eclipseExecutableFile = new File(eclipseInstallDir, "eclipse");
		}
		if (!eclipseExecutableFile.isFile()) {
			throw new FileNotFoundException("Eclipse installation executable file does not exist.");
		}
		return eclipseExecutableFile;
	}


	@Override
	public File getEclipseWorkspaceDir() {
		return options.getFile(EclipseIntegrationOptionsPlugin.ECLIPSE_WORKSPACE_DIR_OPTION, null);
	}

	@Override
	public boolean isEclipseFeatureInstalled(FilenameFilter filter) throws FileNotFoundException {
		File eclipseInstallDir = getEclipseInstallDir();

		// Build up a list of directories to search.  It will consist of the main features 
		// directory, the top-level dropins directory (plugins can live here too), and any 
		// features directories found in the dropins directories.
		List<File> featuresDirs = new ArrayList<>();
		File mainFeaturesDir = new File(eclipseInstallDir, "features");
		if (mainFeaturesDir.isDirectory()) {
			featuresDirs.add(mainFeaturesDir);
		}
		File dropinsDir = new File(eclipseInstallDir, "dropins");
		if (dropinsDir.isDirectory()) {
			featuresDirs.add(dropinsDir);
			for (File dir : dropinsDir.listFiles(File::isDirectory)) {
				for (File subdir : dir.listFiles(File::isDirectory)) {
					if (subdir.getName().equals("features")) {
						featuresDirs.add(subdir);
						break;
					}
				}
			}
		}

		// Search the discovered features directories
		for (File featuresDir : featuresDirs) {
			File[] matches = featuresDir.listFiles(filter);
			if (matches != null && matches.length > 0) {
				return true;
			}
		}

		return false;
	}

	@Override
	public EclipseConnection connectToEclipse(int port) {
		return TaskLauncher.launch(new EclipseConnectorTask(this, port)).getConnection();
	}

	@Override
	public void offerGhidraDevInstallation(TaskMonitor monitor) {
		if (SystemUtilities.isInHeadlessMode()) {
			return;
		}
		
		SystemUtilities.runSwingNow(() -> {

			boolean autoGhidraDevInstall = options.getBoolean(
				EclipseIntegrationOptionsPlugin.AUTO_GHIDRADEV_INSTALL_OPTION, false);

			String errorTitle = "Failed to install GhidraDev";

			if (!autoGhidraDevInstall) {
				int choice = OptionDialog.showYesNoDialog(null, "GhidraDev",
					"GhidraDev has not been installed in Eclipse.\n" +
						"Would you like it automatically installed in Eclipse's \"dropins\" directory?");
				if (choice != OptionDialog.YES_OPTION) {
					return;
				}
			}

			if (SystemUtilities.isInDevelopmentMode()) {
				Msg.showError(this, null, errorTitle,
					"Automatic installation of GhidraDev from development mode is not supported.\n" +
						"Please install it manually.");
				return;
			}

			File dropinsDir;
			try {
				dropinsDir = getEclipseDropinsDir();
			}
			catch (FileNotFoundException e) {
				Msg.showError(this, null, errorTitle, "Eclipse dropins directory does not exist.");
				return;
			}

			File ghidraDevDir = new ResourceFile(Application.getInstallationDirectory(),
				"Extensions/Eclipse/GhidraDev").getFile(false);
			if (ghidraDevDir == null || !ghidraDevDir.isDirectory()) {
				Msg.showError(this, null, errorTitle,
					"GhidraDev directory does not exist in Ghidra:\n" + ghidraDevDir);
				return;
			}

			File ghidraDevFile = null;
			for (File f : ghidraDevDir.listFiles(File::isFile)) {
				if (f.getName().startsWith("GhidraDev") && f.getName().endsWith(".zip")) {
					ghidraDevFile = f;
					break;
				}
			}
			if (ghidraDevFile == null) {
				Msg.showError(this, null, errorTitle,
					"GhidraDev Eclipse extension does not exist:\n" + ghidraDevFile);
				return;
			}
			
			try (ZipFile ghidraDevZip = new ZipFile(ghidraDevFile)) {
				Enumeration<? extends ZipEntry> entries = ghidraDevZip.entries();
				while (entries.hasMoreElements()) {
					ZipEntry entry = entries.nextElement();
					String entryPath = entry.getName();
					String entryName = new File(entryPath).getName();
					if (entryPath.startsWith("plugins") && entryPath.contains("ghidradev")) {
						FileUtilities.copyStreamToFile(ghidraDevZip.getInputStream(entry),
							new File(dropinsDir, entryName), false, monitor);
						break;
					}
				}
			}
			catch (IOException e) {
				Msg.showError(this, null, errorTitle,
					"Error installing GhidraDev to:\n" + dropinsDir, e);
				return;
			}
		});
	}

	@Override
	public void handleEclipseError(String error, boolean askAboutOptions, Throwable t) {
		if (askAboutOptions && !SystemUtilities.isInHeadlessMode()) {
			SystemUtilities.runSwingNow(() -> {
				int choice = OptionDialog.showYesNoDialog(null, "Failed to launch Eclipse",
					error + "\nWould you like to verify your \"" +
						EclipseIntegrationOptionsPlugin.PLUGIN_OPTIONS_NAME + "\" options now?");
				if (choice == OptionDialog.YES_OPTION) {
					AppInfo.getFrontEndTool().getService(OptionsService.class).showOptionsDialog(
						EclipseIntegrationOptionsPlugin.PLUGIN_OPTIONS_NAME, null);
				}
			});
		}
		else {
			Msg.showError(EclipseConnectorTask.class, null, "Failed to launch Eclipse", error, t);
		}
	}

	/**
	 * Gets the Eclipse installation directory.  This is the directory with the eclipse.ini
	 * file in it.
	 * 
	 * @return The Eclipse installation directory.
	 * @throws FileNotFoundException if the installation directory does not exist.
	 */
	private File getEclipseInstallDir() throws FileNotFoundException {
		File eclipseInstallDir =
			options.getFile(EclipseIntegrationOptionsPlugin.ECLIPSE_INSTALL_DIR_OPTION, null);
		if (eclipseInstallDir == null) {
			throw new FileNotFoundException("Eclipse installation directory not defined.");
		}
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.MAC_OS_X) {
			if (eclipseInstallDir.getName().startsWith("Eclipse") &&
				eclipseInstallDir.getName().endsWith(".app")) {
				eclipseInstallDir = new File(eclipseInstallDir, "Contents/Eclipse");
			}
			else if (eclipseInstallDir.getName().equals("Contents")) {
				eclipseInstallDir = new File(eclipseInstallDir, "Eclipse");
			}
			else if (eclipseInstallDir.getName().equals("MacOS") &&
				eclipseInstallDir.getParentFile().getName().equals("Contents")) {
				eclipseInstallDir = new File(eclipseInstallDir.getParentFile(), "Eclipse");
			}
			else if (eclipseInstallDir.getName().equals("Resources") &&
				eclipseInstallDir.getParentFile().getName().equals("Contents")) {
				eclipseInstallDir = new File(eclipseInstallDir.getParentFile(), "Eclipse");
			}
		}
		if (!eclipseInstallDir.isDirectory()) {
			throw new FileNotFoundException("Eclipse installation directory does not exist.");
		}
		return eclipseInstallDir;
	}

	/**
	 * Gets the Eclipse dropins directory.
	 * 
	 * @return The Eclipse dropins directory.
	 * @throws FileNotFoundException if the dropins directory does not exist.
	 */
	public File getEclipseDropinsDir() throws FileNotFoundException {
		File eclipseInstallDir = getEclipseInstallDir();
		File dropinsDir = new File(eclipseInstallDir, "dropins");
		if (!dropinsDir.isDirectory()) {
			throw new FileNotFoundException("Eclipse dropins directory does not exist.");
		}
		return dropinsDir;
	}
}
