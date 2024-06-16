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
package ghidra.framework.project.extensions;

import java.io.File;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import docking.widgets.OkDialog;
import docking.widgets.OptionDialog;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.extensions.*;
import ghidra.util.task.TaskLauncher;
import utility.application.ApplicationLayout;

/**
 * Utility class for managing Ghidra Extensions.
 * <p>
 * Extensions are defined as any archive or folder that contains an <code>extension.properties</code>
 * file. This properties file can contain the following attributes:
 * <ul>
 * <li>name (required)</li>
 * <li>description</li>
 * <li>author</li>
 * <li>createdOn (format: MM/dd/yyyy)</li>
 * <li>version</li>
 * </ul>
 *
 * <p>
 * Extensions may be installed/uninstalled by users at runtime, using the
 * {@link ExtensionTableProvider}. Installation consists of unzipping the extension archive to an
 * installation folder, currently <code>{ghidra user settings dir}/Extensions</code>. To uninstall,
 * the unpacked folder is simply removed.
 */
public class ExtensionInstaller {

	private static final Logger log = LogManager.getLogger(ExtensionInstaller.class);

	/**
	 * Installs the given extension file. This can be either an archive (zip) or a directory that
	 * contains an extension.properties file.
	 *
	 * @param file the extension to install
	 * @return true if the extension was successfully installed
	 */
	public static boolean install(File file) {

		log.trace("Installing extension file " + file);

		if (file == null) {
			log.error("Install file cannot be null");
			return false;
		}

		ExtensionDetails extension = ExtensionUtils.getExtension(file, false);
		if (extension == null) {
			Msg.showError(ExtensionInstaller.class, null, "Error Installing Extension",
				file.getAbsolutePath() + " does not point to a valid ghidra extension");
			return false;
		}

		Extensions extensions = ExtensionUtils.getAllInstalledExtensions();
		if (checkForConflictWithDevelopmentExtension(extension, extensions)) {
			return false;
		}

		if (checkForDuplicateExtensions(extension, extensions)) {
			return false;
		}

		// Verify that the version of the extension is valid for this version of Ghidra. If not,
		// just exit without installing.
		if (!validateExtensionVersion(extension)) {
			return false;
		}

		AtomicBoolean installed = new AtomicBoolean(false);
		TaskLauncher.launchModal("Installing Extension", (monitor) -> {
			installed.set(ExtensionUtils.install(extension, file, monitor));
		});

		boolean success = installed.get();
		if (success) {
			log.trace("Finished installing " + file);
		}
		else {
			log.trace("Failed to install " + file);
		}

		return success;
	}

	/**
	 * Installs the given extension from its declared archive path
	 * @param extension the extension
	 * @return true if successful
	 */
	public static boolean installExtensionFromArchive(ExtensionDetails extension) {
		if (extension == null) {
			log.error("Extension to install cannot be null");
			return false;
		}

		String archivePath = extension.getArchivePath();
		if (archivePath == null) {
			log.error("Cannot install from archive; extension is missing archive path");
			return false;
		}

		ApplicationLayout layout = Application.getApplicationLayout();
		ResourceFile extInstallDir = layout.getExtensionInstallationDirs().get(0);
		String extName = extension.getName();
		File extDestinationDir = new ResourceFile(extInstallDir, extName).getFile(false);
		File archiveFile = new File(archivePath);
		if (install(archiveFile)) {
			extension.setInstallDir(new File(extDestinationDir, extName));
			return true;
		}

		return false;
	}

	/**
	 * Compares the given extension version to the current Ghidra version.  If they are different,
	 * then the user will be prompted to confirm the installation.   This method will return true
	 * if the versions match or the user has chosen to install anyway.
	 *
	 * @param extension the extension
	 * @return true if the versions match or the user has chosen to install anyway
	 */
	private static boolean validateExtensionVersion(ExtensionDetails extension) {
		String extVersion = extension.getVersion();
		if (extVersion == null) {
			extVersion = "<no version>";
		}

		String appVersion = Application.getApplicationVersion();
		if (extVersion.equals(appVersion)) {
			return true;
		}

		String message = "Extension version mismatch.\nName: " + extension.getName() +
			"Extension version: " + extVersion + ".\nGhidra version: " + appVersion + ".";
		int choice = OptionDialog.showOptionDialogWithCancelAsDefaultButton(null,
			"Extension Version Mismatch", message, "Install Anyway");
		if (choice != OptionDialog.OPTION_ONE) {
			log.info(removeNewlines(message + " Did not install"));
			return false;
		}
		return true;
	}

	private static String removeNewlines(String s) {
		return s.replaceAll("\n", " ");
	}

	private static boolean checkForDuplicateExtensions(ExtensionDetails newExtension,
			Extensions extensions) {

		String name = newExtension.getName();
		log.trace("Checking for duplicate extensions for '" + name + "'");

		List<ExtensionDetails> matches = extensions.getMatchingExtensions(newExtension);
		if (matches.isEmpty()) {
			log.trace("No matching extensions installed");
			return false;
		}

		log.trace("Duplicate extensions found by name '" + name + "'");

		if (matches.size() > 1) {
			reportMultipleDuplicateExtensionsWhenInstalling(newExtension, matches);
			return true;
		}

		ExtensionDetails installedExtension = matches.get(0);
		String message =
			"Attempting to install an extension matching the name of an existing extension.\n" +
				"New extension version: " + newExtension.getVersion() + ".\n" +
				"Installed extension version: " + installedExtension.getVersion() + ".\n\n" +
				"To install, click 'Remove Existing', restart Ghidra, then install again.";
		int choice = OptionDialog.showOptionDialogWithCancelAsDefaultButton(null,
			"Duplicate Extension", message, "Remove Existing");

		String installPath = installedExtension.getInstallPath();
		if (choice != OptionDialog.OPTION_ONE) {
			log.info(removeNewlines(message +
				" Skipping installation. Original extension still installed: " + installPath));
			return true;
		}

		//
		// At this point the user would like to replace the existing extension.  We cannot delete
		// the existing extension, as it may be in use; mark it for removal.
		//
		log.info(removeNewlines(
			message + " Installing new extension. Existing extension will be removed after " +
				"restart: " + installPath));
		installedExtension.markForUninstall();
		return true;
	}

	private static void reportMultipleDuplicateExtensionsWhenInstalling(ExtensionDetails extension,
			List<ExtensionDetails> matches) {

		StringBuilder buffy = new StringBuilder();
		buffy.append("Found multiple duplicate extensions while trying to install '")
				.append(extension.getName())
				.append("'\n");
		for (ExtensionDetails otherExtension : matches) {
			buffy.append("Duplicate: " + otherExtension.getInstallPath()).append('\n');
		}
		buffy.append("Please close Ghidra and manually remove from these extensions from the " +
			"filesystem.");

		Msg.showInfo(ExtensionInstaller.class, null, "Duplicate Extensions Found",
			buffy.toString());
	}

	private static boolean checkForConflictWithDevelopmentExtension(ExtensionDetails newExtension,
			Extensions extensions) {

		String name = newExtension.getName();
		log.trace("Checking for duplicate dev mode extensions for '" + name + "'");

		List<ExtensionDetails> matches = extensions.getMatchingExtensions(newExtension);
		if (matches.isEmpty()) {
			log.trace("No matching extensions installed");
			return false;
		}

		for (ExtensionDetails extension : matches) {

			if (extension.isInstalledInInstallationFolder()) {

				String message = "Attempting to install an extension that conflicts with an " +
					"extension located in the Ghidra installation folder.\nYou must manually " +
					"remove the existing extension to install the new extension.\nExisting " +
					"extension: " + extension.getInstallDir();

				log.trace(removeNewlines(message));

				OkDialog.showError("Duplicate Extensions Found", message);
				return true;
			}
		}

		return false;
	}
}
