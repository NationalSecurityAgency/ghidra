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

import java.io.*;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import docking.widgets.OkDialog;
import docking.widgets.OptionDialog;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;
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
public class ExtensionUtils {

	/** Magic number that identifies the first bytes of a ZIP archive. This is used to verify
	 	that a file is a zip rather than just checking the extension. */
	private static final int ZIPFILE = 0x504b0304;

	public static String PROPERTIES_FILE_NAME = "extension.properties";
	public static String PROPERTIES_FILE_NAME_UNINSTALLED = "extension.properties.uninstalled";

	private static final Logger log = LogManager.getLogger(ExtensionUtils.class);

	/**
	 * Performs extension maintenance.  This should be called at startup, before any plugins or 
	 * extension points are loaded.
	 */
	public static void initializeExtensions() {

		Extensions extensions = getAllInstalledExtensions();

		// delete any extensions marked for removal
		extensions.cleanupExtensionsMarkedForRemoval();

		// check for duplicates in the remaining extensions
		extensions.reportDuplicateExtensions();
	}

	/**
	 * Gets all known extensions that have not been marked for removal.
	 *  
	 * @return set of installed extensions
	 */
	public static Set<ExtensionDetails> getActiveInstalledExtensions() {
		Extensions extensions = getAllInstalledExtensions();
		return extensions.getActiveExtensions();
	}

	/**
	 * Returns all installed extensions. These are all the extensions found in
	 * {@link ApplicationLayout#getExtensionInstallationDirs}.
	 * 
	 * @return set of installed extensions
	 */
	public static Set<ExtensionDetails> getInstalledExtensions() {
		Extensions extensions = getAllInstalledExtensions();
		return extensions.get();
	}

	private static Extensions getAllInstalledExtensions() {

		log.trace("Finding all installed extensions...");

		Extensions extensions = new Extensions();

		// Find all extension.properties or extension.properties.uninstalled files in
		// the install directory and create a ExtensionDetails object for each.
		ApplicationLayout layout = Application.getApplicationLayout();
		for (ResourceFile installDir : layout.getExtensionInstallationDirs()) {
			if (!installDir.isDirectory()) {
				continue;
			}

			log.trace("Checking extension installation dir '" + installDir);

			File dir = installDir.getFile(false);
			List<File> propFiles = findExtensionPropertyFiles(dir);
			for (File propFile : propFiles) {

				ExtensionDetails extension = createExtensionFromProperties(propFile);
				if (extension == null) {
					continue;
				}

				// We found this extension in the installation directory, so set the install path
				// property and add to the final set.
				File extInstallDir = propFile.getParentFile();
				extension.setInstallDir(extInstallDir);

				log.trace("Loading extension '" + extension.getName() + "' from: " + extInstallDir);
				extensions.add(extension);
			}
		}

		log.trace(() -> "All installed extensions: " + extensions.getAsString());

		return extensions;
	}

	/**
	 * Returns all archive extensions. These are all the extensions found in
	 * {@link ApplicationLayout#getExtensionArchiveDir}.   This are added to an installation as 
	 * part of the build processes.  
	 * <p>
	 * Archived extensions may be zip files and directories.
	 * 
	 * @return set of archive extensions
	 */
	public static Set<ExtensionDetails> getArchiveExtensions() {

		log.trace("Finding archived extensions");

		ApplicationLayout layout = Application.getApplicationLayout();
		ResourceFile archiveDir = layout.getExtensionArchiveDir();
		if (archiveDir == null) {
			log.trace("No extension archive dir found");
			return Collections.emptySet();
		}

		ResourceFile[] archiveFiles = archiveDir.listFiles();
		if (archiveFiles == null) {
			log.trace("No files in extension archive dir: " + archiveDir);
			return Collections.emptySet(); // no files or dirs inside of the archive directory
		}

		Set<ExtensionDetails> extensions = new HashSet<>();
		findExtensionsInZips(archiveFiles, extensions);
		findExtensionsInFolder(archiveDir.getFile(false), extensions);

		return extensions;
	}

	private static void findExtensionsInZips(ResourceFile[] archiveFiles,
			Set<ExtensionDetails> extensions) {
		for (ResourceFile file : archiveFiles) {
			ExtensionDetails extension = createExtensionDetailsFromArchive(file);
			if (extension == null) {
				log.trace("Skipping archive file; not an extension: " + file);
				continue;
			}

			if (extensions.contains(extension)) {
				log.error(
					"Skipping extension \"" + extension.getName() + "\" found at " +
						extension.getInstallPath() +
						".\nArchived extension by that name already found.");
			}
			extensions.add(extension);
		}
	}

	private static void findExtensionsInFolder(File dir, Set<ExtensionDetails> extensions) {
		List<File> propFiles = findExtensionPropertyFiles(dir);
		for (File propFile : propFiles) {
			ExtensionDetails extension = createExtensionFromProperties(propFile);
			if (extension == null) {
				continue;
			}

			// We found this extension in the installation directory, so set the archive path
			// property and add to the final set.
			File extDir = propFile.getParentFile();
			extension.setArchivePath(extDir.getAbsolutePath());

			if (extensions.contains(extension)) {
				log.error(
					"Skipping duplicate extension \"" + extension.getName() + "\" found at " +
						extension.getInstallPath());
			}
			extensions.add(extension);
		}
	}

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

		ExtensionDetails extension = getExtension(file, false);
		if (extension == null) {
			Msg.showError(ExtensionUtils.class, null, "Error Installing Extension",
				file.getAbsolutePath() + " does not point to a valid ghidra extension");
			return false;
		}

		Extensions extensions = getAllInstalledExtensions();
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
			installed.set(doRunInstallTask(extension, file, monitor));
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

	private static boolean doRunInstallTask(ExtensionDetails extension, File file,
			TaskMonitor monitor) {
		try {
			if (file.isFile()) {
				return unzipToInstallationFolder(extension, file, monitor);
			}

			return copyToInstallationFolder(file, monitor);
		}
		catch (CancelledException e) {
			log.info("Extension installation cancelled by user");
		}
		catch (IOException e) {
			Msg.showError(ExtensionUtils.class, null, "Error Installing Extension",
				"Unexpected error installing extension", e);
		}
		return false;
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
			log.error(
				"Cannot install from archive; extension is missing archive path");
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
			"Extension Version Mismatch",
			message,
			"Install Anyway");
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
			"Duplicate Extension",
			message,
			"Remove Existing");

		String installPath = installedExtension.getInstallPath();
		if (choice != OptionDialog.OPTION_ONE) {
			log.info(
				removeNewlines(
					message + " Skipping installation. Original extension still installed: " +
						installPath));
			return true;
		}

		//
		// At this point the user would like to replace the existing extension.  We cannot delete
		// the existing extension, as it may be in use; mark it for removal.
		//
		log.info(
			removeNewlines(
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

		Msg.showInfo(ExtensionUtils.class, null, "Duplicate Extensions Found", buffy.toString());
	}

	private static void reportDuplicateExtensionsWhenLoading(String name,
			List<ExtensionDetails> extensions) {

		ExtensionDetails loadedExtension = extensions.get(0);
		File loadedInstallDir = loadedExtension.getInstallDir();

		for (int i = 1; i < extensions.size(); i++) {
			ExtensionDetails duplicate = extensions.get(i);
			log.info("Duplicate extension found '" + name + "'.  Keeping extension from " +
				loadedInstallDir + ".  Skipping extension found at " +
				duplicate.getInstallDir());
		}
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

	/**
	 * Returns true if the given file or directory is a valid ghidra extension.
	 * <p>
	 * Note: This means that the zip or directory contains an extension.properties file.
	 * 
	 * @param file the zip or directory to inspect
	 * @return true if the given file represents a valid extension
	 */
	public static boolean isExtension(File file) {
		return getExtension(file, true) != null;
	}

	private static ExtensionDetails getExtension(File file, boolean quiet) {

		if (file == null) {
			log.error("Cannot get an extension; null file");
			return null;
		}

		try {
			return tryToGetExtension(file);
		}
		catch (IOException e) {
			if (quiet) {
				log.trace("Exception trying to read an extension from " + file, e);
			}
			else {
				log.error("Exception trying to read an extension from " + file, e);
			}
		}
		return null;
	}

	private static ExtensionDetails tryToGetExtension(File file) throws IOException {

		if (file == null) {
			log.error("Cannot get an extension; null file");
			return null;
		}

		if (file.isDirectory() && file.canRead()) {
			File[] files = file.listFiles(f -> f.getName().equals(PROPERTIES_FILE_NAME));
			if (files != null && files.length == 1) {
				return tryToLoadExtensionFromProperties(files[0]);
			}
		}

		// If the given file is a zip, it's an extension if there's an extension.properties
		// file at the TOP LEVEL ONLY; we don't want to search for nested property files (this
		// would cause us to match things like the main ghidra distribution zip file.
		// eg: DatabaseTools/extension.properties is valid
		//     DatabaseTools/foo/extension.properties is not.
		if (isZip(file)) {
			try (ZipFile zipFile = new ZipFile(file)) {
				Properties props = getProperties(zipFile);
				if (props != null) {
					return createExtensionDetails(props);
				}
				throw new IOException("No extension.properties file found in zip");
			}
		}

		return null;
	}

	/**
	 * Returns true if the given file is a valid .zip archive.
	 * 
	 * @param file the file to test
	 * @return true if file is a valid zip
	 */
	private static boolean isZip(File file) {

		if (file == null) {
			log.error("Cannot check for extension zip; null file");
			return false;
		}

		if (file.isDirectory()) {
			return false;
		}

		if (file.length() < 4) {
			return false;
		}

		try (DataInputStream in =
			new DataInputStream(new BufferedInputStream(new FileInputStream(file)))) {
			int test = in.readInt();
			return test == ZIPFILE;
		}
		catch (IOException e) {
			log.trace("Unable to check if file is a zip file: " + file + ". " + e.getMessage());
			return false;
		}
	}

	/**
	 * Returns a list of files representing all the <code>extension.properties</code> files found
	 * under a given directory. This will only search the immediate children of the given directory.
	 * <p>
	 * Searching the child directories of a directory allows clients to pick an extension parent
	 * directory that contains multiple extension directories.
	 * 
	 * @param installDir the directory that contains extension subdirectories 
	 * @return list of extension.properties files
	 */
	private static List<File> findExtensionPropertyFiles(File installDir) {

		List<File> results = new ArrayList<>();
		FileUtilities.forEachFile(installDir, f -> {
			if (!f.isDirectory() || f.getName().equals("Skeleton")) {
				return;
			}

			File pf = getPropertyFile(f);
			if (pf != null) {
				results.add(pf);
			}
		});

		return results;
	}

	/**
	 * Returns an extension.properties or extension.properties.uninstalled file if the given 
	 * directory contains one.
	 * 
	 * @param dir the directory to search
	 * @return the file, or null if doesn't exist
	 */
	private static File getPropertyFile(File dir) {

		File f = new File(dir, PROPERTIES_FILE_NAME_UNINSTALLED);
		if (f.exists()) {
			return f;
		}

		f = new File(dir, PROPERTIES_FILE_NAME);
		if (f.exists()) {
			return f;
		}

		return null;
	}

	private static ExtensionDetails createExtensionDetailsFromArchive(ResourceFile resourceFile) {

		File file = resourceFile.getFile(false);
		if (!isZip(file)) {
			return null;
		}

		try (ZipFile zipFile = new ZipFile(file)) {
			Properties props = getProperties(zipFile);
			if (props != null) {
				ExtensionDetails extension = createExtensionDetails(props);
				extension.setArchivePath(file.getAbsolutePath());
				return extension;
			}
		}
		catch (IOException e) {
			log.error(
				"Unable to read zip file to get extension properties: " + file, e);
		}
		return null;
	}

	private static Properties getProperties(ZipFile zipFile) throws IOException {

		Properties props = null;
		Enumeration<ZipArchiveEntry> zipEntries = zipFile.getEntries();
		while (zipEntries.hasMoreElements()) {
			ZipArchiveEntry entry = zipEntries.nextElement();
			Properties nextProperties = getProperties(zipFile, entry);
			if (nextProperties != null) {
				if (props != null) {
					throw new IOException(
						"Zip file contains multiple extension properties files");
				}
				props = nextProperties;
			}

		}
		return props;
	}

	private static Properties getProperties(ZipFile zipFile, ZipArchiveEntry entry)
			throws IOException {
		// We only search for the property file at the top level
		String path = entry.getName();
		List<String> parts = FileUtilities.pathToParts(path);
		if (parts.size() != 2) { // require 2 parts: dir name / props file
			return null;
		}

		if (!entry.getName().endsWith(PROPERTIES_FILE_NAME)) {
			return null;
		}

		InputStream propFile = zipFile.getInputStream(entry);
		Properties prop = new Properties();
		prop.load(propFile);
		return prop;
	}

	/**
	 * Copies the given folder to the extension install location. Any existing folder at that
	 * location will be deleted.
	 * <p>
	 * Note: Any existing folder with the same name will be overwritten.
	 * 
	 * @param sourceFolder the extension folder
	 * @param monitor the task monitor
	 * @return true if successful
	 * @throws IOException if the delete or copy fails
	 * @throws CancelledException if the user cancels the copy
	 */
	private static boolean copyToInstallationFolder(File sourceFolder, TaskMonitor monitor)
			throws IOException, CancelledException {

		log.trace("Copying extension from " + sourceFolder);

		ApplicationLayout layout = Application.getApplicationLayout();
		ResourceFile installDir = layout.getExtensionInstallationDirs().get(0);
		File installDirRoot = installDir.getFile(false);
		File newDir = new File(installDirRoot, sourceFolder.getName());
		if (hasExistingExtension(newDir, monitor)) {
			return false;
		}

		log.trace("Copying extension to " + newDir);
		FileUtilities.copyDir(sourceFolder, newDir, monitor);
		return true;
	}

	private static boolean hasExistingExtension(File extensionFolder, TaskMonitor monitor) {

		if (extensionFolder.exists()) {
			Msg.showWarn(ExtensionUtils.class, null, "Duplicate Extension Folder",
				"Attempting to install a new extension over an existing directory.\n" +
					"Either remove the extension for that directory from the UI\n" +
					"or close Ghidra and delete the directory and try installing again.\n\n" +
					"Directory: " + extensionFolder);
			return true;
		}
		return false;
	}

	/**
	 * Unpacks a given zip file to {@link ApplicationLayout#getExtensionInstallationDirs}. The
	 * file permissions in the original zip will be retained.
	 * <p>
	 * Note: This method uses the Apache zip files since they keep track of permissions info;
	 * the built-in java objects (e.g., ZipEntry) do not.
	 * 
	 * @param extension the extension
	 * @param file the zip file to unpack
	 * @param monitor the task monitor
	 * @return true if successful
	 * @throws IOException if any part of the unzipping fails, or if the target location is invalid
	 * @throws CancelledException if the user cancels the unzip
	 * @throws IOException if error unzipping zip file
	 */
	private static boolean unzipToInstallationFolder(ExtensionDetails extension, File file,
			TaskMonitor monitor)
			throws CancelledException, IOException {

		log.trace("Unzipping extension from " + file);

		ApplicationLayout layout = Application.getApplicationLayout();
		ResourceFile installDir = layout.getExtensionInstallationDirs().get(0);
		File installDirRoot = installDir.getFile(false);
		File destinationFolder = new File(installDirRoot, extension.getName());
		if (hasExistingExtension(destinationFolder, monitor)) {
			return false;
		}

		try (ZipFile zipFile = new ZipFile(file)) {

			Enumeration<ZipArchiveEntry> entries = zipFile.getEntries();
			while (entries.hasMoreElements()) {
				monitor.checkCancelled();

				ZipArchiveEntry entry = entries.nextElement();
				String filePath = installDir + File.separator + entry.getName();
				File destination = new File(filePath);
				if (entry.isDirectory()) {
					destination.mkdirs();
				}
				else {
					writeZipEntryToFile(zipFile, entry, destination);
				}
			}
		}
		return true;
	}

	private static void writeZipEntryToFile(ZipFile zFile, ZipArchiveEntry entry, File destination)
			throws IOException {
		try (OutputStream outputStream =
			new BufferedOutputStream(new FileOutputStream(destination))) {

			// Create the file at the new location...
			IOUtils.copy(zFile.getInputStream(entry), outputStream);

			// ...and update its permissions. But only continue if the zip was created on a unix
			//platform. If not, we cannot use the posix libraries to set permissions.
			if (entry.getPlatform() != ZipArchiveEntry.PLATFORM_UNIX) {
				return;
			}

			int mode = entry.getUnixMode();
			if (mode != 0) { // 0 indicates non-unix platform
				Set<PosixFilePermission> perms = getPermissions(mode);
				try {
					Files.setPosixFilePermissions(destination.toPath(), perms);
				}
				catch (UnsupportedOperationException e) {
					// Need to catch this, as Windows does not support the posix call. This is not
					// an error, however, and should just silently fail.
				}
			}
		}
	}

	private static ExtensionDetails tryToLoadExtensionFromProperties(File file) throws IOException {

		Properties props = new Properties();
		try (InputStream in = new FileInputStream(file.getAbsolutePath())) {
			props.load(in);
			return createExtensionDetails(props);
		}
	}

	private static ExtensionDetails createExtensionFromProperties(File file) {
		try {
			return tryToLoadExtensionFromProperties(file);
		}
		catch (IOException e) {
			log.error("Error loading extension properties from " + file.getAbsolutePath(), e);
			return null;
		}
	}

	private static ExtensionDetails createExtensionDetails(Properties props) {

		String name = props.getProperty("name");
		String desc = props.getProperty("description");
		String author = props.getProperty("author");
		String date = props.getProperty("createdOn");
		String version = props.getProperty("version");

		return new ExtensionDetails(name, desc, author, date, version);
	}

	/**
	 * Uninstalls a given extension.
	 * 
	 * @param extension the extension to uninstall
	 * @return true if successfully uninstalled
	 */
	private static boolean removeExtension(ExtensionDetails extension) {

		if (extension == null) {
			log.error("Extension to uninstall cannot be null");
			return false;
		}

		File installDir = extension.getInstallDir();
		if (installDir == null) {
			log.error("Extension installation path is not set; unable to delete files");
			return false;
		}

		if (FileUtilities.deleteDir(installDir)) {
			extension.setInstallDir(null);
			return true;
		}

		return false;
	}

	/**
	 * Converts Unix permissions to a set of {@link PosixFilePermission}s.
	 * 
	 * @param unixMode integer representation of file permissions
	 * @return set of POSIX file permissions
	 */
	private static Set<PosixFilePermission> getPermissions(int unixMode) {

		Set<PosixFilePermission> permissions = new HashSet<>();

		if ((unixMode & 0400) != 0) {
			permissions.add(PosixFilePermission.OWNER_READ);
		}
		if ((unixMode & 0200) != 0) {
			permissions.add(PosixFilePermission.OWNER_WRITE);
		}
		if ((unixMode & 0100) != 0) {
			permissions.add(PosixFilePermission.OWNER_EXECUTE);
		}
		if ((unixMode & 0040) != 0) {
			permissions.add(PosixFilePermission.GROUP_READ);
		}
		if ((unixMode & 0020) != 0) {
			permissions.add(PosixFilePermission.GROUP_WRITE);
		}
		if ((unixMode & 0010) != 0) {
			permissions.add(PosixFilePermission.GROUP_EXECUTE);
		}
		if ((unixMode & 0004) != 0) {
			permissions.add(PosixFilePermission.OTHERS_READ);
		}
		if ((unixMode & 0002) != 0) {
			permissions.add(PosixFilePermission.OTHERS_WRITE);
		}
		if ((unixMode & 0001) != 0) {
			permissions.add(PosixFilePermission.OTHERS_EXECUTE);
		}

		return permissions;
	}

	/**
	 * A collection of all extensions found.  This class provides methods processing duplicates and
	 * managing extensions marked for removal.
	 */
	private static class Extensions {

		private Map<String, List<ExtensionDetails>> extensionsByName = new HashMap<>();

		void add(ExtensionDetails e) {
			extensionsByName.computeIfAbsent(e.getName(), n -> new ArrayList<>()).add(e);
		}

		Set<ExtensionDetails> getActiveExtensions() {
			return extensionsByName.values()
					.stream()
					.map(list -> list.get(0))
					.filter(ext -> !ext.isPendingUninstall())
					.collect(Collectors.toSet());
		}

		List<ExtensionDetails> getMatchingExtensions(ExtensionDetails extension) {
			return extensionsByName.computeIfAbsent(extension.getName(), name -> List.of());
		}

		void cleanupExtensionsMarkedForRemoval() {

			Set<String> names = new HashSet<>(extensionsByName.keySet());
			for (String name : names) {
				List<ExtensionDetails> extensions = extensionsByName.get(name);
				Iterator<ExtensionDetails> it = extensions.iterator();
				while (it.hasNext()) {
					ExtensionDetails extension = it.next();
					if (!extension.isPendingUninstall()) {
						continue;
					}
					if (!removeExtension(extension)) {
						log.error("Error removing extension: " + extension.getInstallPath());
					}

					it.remove();
				}

				if (extensions.isEmpty()) {
					extensionsByName.remove(name);
				}
			}
		}

		void reportDuplicateExtensions() {

			Set<Entry<String, List<ExtensionDetails>>> entries = extensionsByName.entrySet();
			for (Entry<String, List<ExtensionDetails>> entry : entries) {
				List<ExtensionDetails> list = entry.getValue();
				if (list.size() == 1) {
					continue;
				}

				reportDuplicateExtensionsWhenLoading(entry.getKey(), list);
			}
		}

		/**
		 * Returns all unique (no duplicates) extensions that the application is aware of
		 * @return the extensions
		 */
		Set<ExtensionDetails> get() {
			return extensionsByName.values()
					.stream()
					.map(list -> list.get(0))
					.collect(Collectors.toSet());
		}

		String getAsString() {
			StringBuilder buffy = new StringBuilder();

			Set<Entry<String, List<ExtensionDetails>>> entries = extensionsByName.entrySet();
			for (Entry<String, List<ExtensionDetails>> entry : entries) {
				String name = entry.getKey();
				buffy.append("Name: ").append(name);

				List<ExtensionDetails> extensions = entry.getValue();
				if (extensions.size() == 1) {
					buffy.append(" - ").append(extensions.get(0).getInstallDir()).append('\n');
				}
				else {
					for (ExtensionDetails e : extensions) {
						buffy.append("\t").append(e.getInstallDir()).append('\n');
					}
				}
			}

			if (buffy.isEmpty()) {
				return "<no extensions installed>";
			}

			if (!buffy.isEmpty()) {
				// remove trailing newline to keep logging consistent
				buffy.deleteCharAt(buffy.length() - 1);
			}
			return buffy.toString();
		}
	}
}
