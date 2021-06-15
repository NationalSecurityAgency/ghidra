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
package ghidra.framework.plugintool.dialog;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipFile;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.lang3.StringUtils;

import docking.DockingWindowManager;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.options.PreferenceState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.dialog.ExtensionException.ExtensionExceptionType;
import ghidra.framework.project.tool.GhidraTool;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

/**
 * Utility class for managing Ghidra Extensions. 
 * <p>
 * Extensions are defined as any archive or folder that contains an <code>extension.properties</code>
 * file. This properties file can contain the following attributes:
 * <ul>
 * <li>name (required)</li>
 * <li>description</li>
 * <li>author</li>
 * <li>createdOn (format: mm/dd/yyyy)</li>
 * </ul>
 * 
 *  Extensions may be installed/uninstalled by users at runtime, using the {@link ExtensionTableProvider}. 
 *  Installation consists of unzipping the extension archive to an installation folder, currently 
 *  <code>Ghidra/Extensions</code>. To uninstall, the unpacked folder is simply removed.
 */
public class ExtensionUtils {

	/** Magic number that identifies the first bytes of a ZIP archive. This is used to verify 
	 	that a file is a zip rather than just checking the extension. */
	private static final int ZIPFILE = 0x504b0304;

	public static String PROPERTIES_FILE_NAME = "extension.properties";
	public static String PROPERTIES_FILE_NAME_UNINSTALLED = "extension.properties.uninstalled";

	/**
	 * Returns a set of all extensions known to Ghidra, represented by
	 * {@link ExtensionDetails} objects. This will include all installed
	 * AND archived extensions.
	 * <p>
	 * Note that this method will only look in the known extension folder locations:
	 * <ul>
	 * <li>{@link ApplicationLayout#getExtensionArchiveDir}</li>
	 * <li>{@link ApplicationLayout#getExtensionInstallationDirs}</li>
	 * </ul>
	 * If users install extensions from other locations, the installed version of 
	 * the extension will be known, but the source archive location will not be retained.
	 * 
	 * @return list of unique extensions
	 * @throws ExtensionException if extensions cannot be retrieved
	 */
	public static Set<ExtensionDetails> getExtensions() throws ExtensionException {

		Set<ExtensionDetails> allExtensions = new HashSet<>();

		// First grab anything in the archive and install directories. 
		Set<ExtensionDetails> archived = getArchivedExtensions();
		Set<ExtensionDetails> installed = getInstalledExtensions(false);

		// Now we need to combine the two lists. For items that are in both lists, we have to ensure
		// that the one we return in the final list has all attributes from both
		// versions. 
		//
		// Note that we prefer attributes in the installed version over the archived version; this is
		// because users may manually update the .properties file at runtime, but only for the installed
		// version - this is how we ensure that the dialog reflects those changes.
		for (ExtensionDetails archivedExtension : archived) {
			for (ExtensionDetails installedExtension : installed) {
				if (installedExtension.equals(archivedExtension)) {
					archivedExtension.setInstallPath(installedExtension.getInstallPath());
					archivedExtension.setAuthor(installedExtension.getAuthor());
					archivedExtension.setCreatedOn(installedExtension.getCreatedOn());
					archivedExtension.setName(installedExtension.getName());
					archivedExtension.setDescription(installedExtension.getDescription());
					break;
				}
			}
		}

		allExtensions.addAll(archived);

		// Finally add all the installed extensions that aren't in the archive set we 
		// just added. Because these are sets, we're ensuring there aren't any dupes.
		allExtensions.addAll(installed);

		return allExtensions;
	}

	/**
	 * Returns all installed extensions. These are all the extensions found in
	 * {@link ApplicationLayout#getExtensionInstallationDirs}.
	 * 
	 * @param includeUninstalled if true, include extensions that have been marked for removal
	 * @return set of installed extensions
	 * @throws ExtensionException if the extension details cannot be retrieved
	 */
	public static Set<ExtensionDetails> getInstalledExtensions(boolean includeUninstalled)
			throws ExtensionException {

		ApplicationLayout layout = Application.getApplicationLayout();

		// The set to return;
		Set<ExtensionDetails> extensions = new HashSet<>();

		// Find all extension.properties or extension.properties.uninstalled files in
		// the install directory and create a ExtensionDetails object for each.
		for (ResourceFile installDir : layout.getExtensionInstallationDirs()) {
			if (!installDir.isDirectory()) {
				continue;
			}
			List<ResourceFile> propFiles =
				findExtensionPropertyFiles(installDir, includeUninstalled);
			for (ResourceFile propFile : propFiles) {

				ExtensionDetails details = createExtensionDetailsFromPropertyFile(propFile);

				// We found this extension in the installation directory, so set the install path
				// property and add to the final set.
				details.setInstallPath(propFile.getParentFile().getAbsolutePath());
				if (!extensions.contains(details)) {
					extensions.add(details);
				}
				else {
					Msg.warn(null,
						"Skipping extension \"" + details.getName() + "\" found at " +
							details.getInstallPath() +
							". Extension by that name installed in higher priority location.");
				}
			}
		}

		return extensions;
	}

	/**
	 * Returns all archived extensions. These are all the extensions found in
	 * {@link ApplicationLayout#getExtensionArchiveDir}.
	 * 
	 * @return set of archived extensions
	 * @throws ExtensionException if the extension details cannot be retrieved
	 */
	public static Set<ExtensionDetails> getArchivedExtensions() throws ExtensionException {

		ApplicationLayout layout = Application.getApplicationLayout();

		if (layout.getExtensionArchiveDir() == null ||
			layout.getExtensionArchiveDir().listFiles() == null) {
			return Collections.emptySet();
		}

		// The set to return;
		Set<ExtensionDetails> extensions = new HashSet<>();

		// Get the archive dir.
		ResourceFile archiveDir = layout.getExtensionArchiveDir();

		// Find any extension.properties files and create extension details objects
		// from them.
		List<ResourceFile> propFiles = findExtensionPropertyFiles(archiveDir, false);
		for (ResourceFile propFile : propFiles) {
			ExtensionDetails details = createExtensionDetailsFromPropertyFile(propFile);

			// We found this extension in the installation directory, so set the install path
			// property and add to the final set.
			details.setArchivePath(propFile.getParentFile().getAbsolutePath());
			extensions.add(details);
		}

		// Now find any .zip archive files and extract the extension properties from them.
		ResourceFile[] rFiles = archiveDir.listFiles();
		if (rFiles != null) {
			for (ResourceFile rFile : rFiles) {
				File file = rFile.getFile(false);
				if (isZip(file)) {
					Properties props = getPropertiesFromArchive(file);
					if (props != null) {
						ExtensionDetails details = createExtensionDetailsFromProperties(props);
						details.setArchivePath(file.getAbsolutePath());
						extensions.add(details);
					}
				}
			}
		}

		return extensions;
	}

	/**
	 * Returns true if an extension with the given name exists in the install folder.
	 * 
	 * @param extensionName the name of the extension
	 * @return true if installed
	 */
	public static boolean isInstalled(String extensionName) {
		for (ResourceFile installDir : Application.getApplicationLayout()
				.getExtensionInstallationDirs()) {
			if (new ResourceFile(installDir, extensionName).exists()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Installs the given extension file. This can be either an archive (zip) or a 
	 * directory that contains an extension.properties file.
	 * 
	 * @param rFile the extension to install
	 * @return true if the extension was successfully installed
	 */
	public static boolean install(ResourceFile rFile) {

		if (rFile == null) {
			Msg.warn(null, "Install file cannot be null");
			return false;
		}

		try {
			if (!isExtension(rFile)) {
				Msg.warn(null,
					rFile.getAbsolutePath() + " does not point to a valid ghidra extension");
				return false;
			}
		}
		catch (ExtensionException e) {
			Msg.warn(null, rFile.getAbsolutePath() + " does not point to a valid ghidra extension",
				e);
			return false;
		}

		return runInstallTask(rFile.getFile(false));
	}

	/**
	 * Installs the given extension.
	 * 
	 * @param extension the extension to install
	 * @param overwrite if true, any existing extension will be overwritten
	 * @return true if the install was successful
	 */
	public static boolean install(ExtensionDetails extension, boolean overwrite) {

		if (extension == null) {
			Msg.warn(null, "Extension to install cannot be null");
			return false;
		}

		File installDir = new ResourceFile(
			Application.getApplicationLayout().getExtensionInstallationDirs().get(0),
			extension.getName()).getFile(false);

		if (extension.getArchivePath() == null) {
			// Special Case: If the archive path is null then this must be an extension that 
			// was installed from an external location, then uninstalled. In this case, there
			// should be a Module.manifest.uninstalled and extension.properties.uninstalled
			// present. If so, just restore them. If not, there's a problem.
			if (installDir.exists()) {
				return restoreStateFiles(installDir);
			}

			return false;
		}

		// Verify that the version of the extension is valid for this version of Ghidra. If not,
		// just exit without installing.
		String ghidraVersion = Application.getApplicationVersion();
		if (!extension.getVersion().equals(ghidraVersion)) {
			Msg.warn(null, "Extension version for [" + extension.getName() +
				"] does not match Ghidra version; cannot install.");
			return false;
		}

		ResourceFile file = new ResourceFile(extension.getArchivePath());

		// We need to handle a special case: If the user selects an extension to uninstall using 
		// the GUI then tries to reinstall it without restarting Ghidra, the extension hasn't actually
		// been removed yet; just the manifest file has been renamed. In this case we don't need to go through 
		// the full install process of unzipping or copying files to the install location. All we need
		// to do is rename the manifest file from Module.manifest.uninstall back to Module.manifest.	
		if (installDir.exists()) {
			return restoreStateFiles(installDir);
		}

		if (install(file)) {
			extension.setInstallPath(installDir + File.separator + extension.getName());
			return true;
		}

		return false;
	}

	/**
	 * Uninstalls a given extension.
	 * 
	 * @param extension the extension to uninstall
	 * @return true if successfully uninstalled
	 */
	public static boolean uninstall(ExtensionDetails extension) {

		if (extension == null) {
			Msg.warn(null, "Extension to uninstall cannot be null");
			return false;
		}

		String installPathStr = extension.getInstallPath();
		if (installPathStr == null || installPathStr.isEmpty()) {
			Msg.warn(null, "Extension is not installed");
			return false;
		}
		Path installPath = Paths.get(installPathStr);
		if (FileUtilities.deleteDir(installPath.toFile())) {
			extension.setInstallPath(null);
			return true;
		}

		return false;
	}

	/**
	 * Returns true if the given file or directory is a valid ghidra extension.
	 * <p>
	 * Note: This means that the zip or directory contains an extension.properties file.
	 * 
	 * @param rFile the resource zip or directory to inspect
	 * @return true if the given file represents a valid extension
	 * @throws ExtensionException if there's an error processing a zip file
	 */
	public static boolean isExtension(ResourceFile rFile) throws ExtensionException {

		if (rFile == null) {
			Msg.warn(null, "File to inspect cannot be null");
			return false;
		}

		// Get the file object associated with this resource
		File file = rFile.getFile(false);

		if (file == null) {
			return false;
		}

		// If the given file is a zip, it's an extension if there's an extension.properties
		// file at the TOP LEVEL ONLY; we don't want to search for nested property files (this 
		// would cause us to match things like the main ghidra distribution zip file.
		// eg: DatabaseTools/extension.properties is valid
		//     DatabaseTools/foo/extension.properties is no.
		if (ExtensionUtils.isZip(file)) {
			try (ZipFile zipFile = new ZipFile(file)) {
				Enumeration<ZipArchiveEntry> zipEntries = zipFile.getEntries();
				while (zipEntries.hasMoreElements()) {
					ZipArchiveEntry entry = zipEntries.nextElement();

					// This is a bit ugly, but to ensure we only search for the property file at the
					// top level, only inspect file names that contain a single path separator. 
					// Also normalize the file path so separators (slashes) are checked correctly
					// on any platform.
					// 
					// Note: We have a PathUtilties method for this, but this package cannot access it and
					// i don't want to add a dependency just for this case.
					String path = entry.getName();
					path = path.replace('\\', '/');
					int separatorCount = StringUtils.countMatches(entry.getName(), '/');
					if (separatorCount == 1) {
						if (entry.getName().endsWith(PROPERTIES_FILE_NAME)) {
							return true;
						}
					}
				}

				return false;
			}
			catch (IOException e) {
				throw new ExtensionException(e.getMessage(), ExtensionExceptionType.ZIP_ERROR);
			}
		}
		else if (file.isDirectory() && file.canRead()) {
			File[] files = file.listFiles();
			if (files != null) {
				for (File f : files) {
					if (f.getName().equals(PROPERTIES_FILE_NAME)) {
						return true;
					}
				}
			}
		}

		return false;
	}

	/**
	 * Returns true if the given file is a valid .zip archive.
	 * 
	 * @param file the file to test
	 * @return true if file is a valid zip
	 * @throws ExtensionException if there's an error reading the zip file
	 */
	public static boolean isZip(File file) throws ExtensionException {

		if (file == null) {
			Msg.warn(null, "File to inspect cannot be null");
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
			throw new ExtensionException(e.getMessage(), ExtensionExceptionType.ZIP_ERROR);
		}
	}

	/**
	 * Returns a list of files representing all the <code>extension.properties</code> files found
	 * under a given directory. This will ONLY search the given directory and its immediate children. 
	 * The conops are as follows:
	 * <ul>
	 * <li>If sourceFile is a directory and it contains an extension.properties file, then that file is returned</li>
	 * <li>If sourceFile does not contain an extension.properties file, then any immediate directories are searched (ignoring Skeleton directory)</li>
	 * </ul>
	 * <p>
	 * Note: This will NOT search zip files. If you have a zip, call {@link #getPropertiesFromArchive(File)} 
	 * instead.
	 * 
	 * @param sourceFile the directory to inspect
	 * @param includeUninstalled if true, include extensions that have been marked for removal
	 * @return list of extension.properties files
	 */
	public static List<ResourceFile> findExtensionPropertyFiles(ResourceFile sourceFile,
			boolean includeUninstalled) {
		List<ResourceFile> propertyFiles = new ArrayList<>();

		// Search for the file in the current directory.
		ResourceFile propFile = findExtensionPropertyFile(sourceFile);
		if (propFile != null) {
			propertyFiles.add(propFile);
			return propertyFiles;
		}

		ResourceFile[] rfiles = sourceFile.listFiles();
		if (rfiles != null) {
			List<ResourceFile> tempFiles = Arrays.asList(rfiles);

			// The given directory didn't contain the file, so search the immediate children.
			if (tempFiles != null && !tempFiles.isEmpty()) {
				for (ResourceFile rFile : tempFiles) {
					if (rFile.isDirectory() && !rFile.getName().equals("Skeleton")) {
						ResourceFile pf = findExtensionPropertyFile(rFile);
						if (pf != null) {
							propertyFiles.add(pf);
						}
					}
				}
			}
		}

		return propertyFiles;
	}

	/**
	 * Returns an extension.properties file if the given directory contains one at the
	 * top level.
	 * 
	 * @param dir the directory to search
	 * @return a ResourceFile representing the extension.properties file, or null if doesn't exist
	 */
	private static ResourceFile findExtensionPropertyFile(ResourceFile dir) {
		if (dir == null || !dir.isDirectory()) {
			return null;
		}

		ResourceFile[] rfiles = dir.listFiles();
		List<ResourceFile> tempFiles = Arrays.asList(rfiles);

		Optional<ResourceFile> file =
			tempFiles.stream()
					.filter(f -> f.getName().equals(PROPERTIES_FILE_NAME) ||
						f.getName().equals(PROPERTIES_FILE_NAME_UNINSTALLED))
					.findFirst();
		if (file.isPresent()) {
			return file.get();
		}

		return null;
	}

	/**
	 * Uses the {@link TaskLauncher} to run a separate task to perform the unzipping/copying
	 * part of the install task. These operations are potentially long-running and need to be
	 * cancelable.
	 * 
	 * @param file the file to install (either a zip or directory)
	 * @return true if the install was successful
	 */
	private static boolean runInstallTask(File file) {

		// Keeps track of whether the install operation succeeds or fails. Must use AtomicBoolean 
		// so we can safely update the value in the task thread.
		AtomicBoolean installed = new AtomicBoolean(false);

		TaskLauncher.launchModal("Installing Extension", (monitor) -> {
			try {
				if (file.isFile()) {
					unzipToInstallationFolder(file, monitor);
				}
				else {
					copyToInstallationFolder(file, monitor);
				}
				installed.set(true);
			}
			catch (ExtensionException e) {
				// If there's a problem copying files, check to see if there's already an extension 
				// with this name in the install location that was slated for removal. If so, just 
				// restore the extension properties and manifest files. 
				if (e.getExceptionType() == ExtensionExceptionType.COPY_ERROR ||
					e.getExceptionType() == ExtensionExceptionType.DUPLICATE_FILE_ERROR) {

					File errorFile = e.getErrorFile();
					if (errorFile != null) {
						// Get the root of the extension in the install location.
						ResourceFile installDir = Application.getApplicationLayout()
								.getExtensionInstallationDirs()
								.get(0);

						// Get the root directory of the extension (strip off the install folder location and
						// grab the first part of the remaining path).
						//
						// eg: If errorFile is "/Users/johnG/Ghidra/Extensions/MyExtensionName/subdir1/problemFile"
						//     And installDir is "/Users/johnG/Ghidra/Extensions"
						//     We need to get "MyExtensionName"
						String extPath = errorFile.getAbsolutePath()
								.substring(installDir.getAbsolutePath().length() + 1);
						int slashIndex = extPath.indexOf(File.separator);
						String extName;
						if (slashIndex == -1) {
							extName = extPath;
						}
						else {
							extName = extPath.substring(0, extPath.indexOf(File.separator));
						}

						boolean success = restoreStateFiles(
							new File(installDir.getAbsolutePath() + File.separator + extName));

						installed.set(success);
					}
				}

				if (installed.get() == false) {
					Msg.showError(null, null, "Installation Error", "Error installing extension [" +
						file.getName() + "]." + " " + e.getExceptionType());
				}
			}
			catch (CancelledException e) {
				Msg.info(null, "Extension installation cancelled by user");
			}
			catch (IOException e) {
				Msg.info(null, "Error installing extension", e);
			}
		});

		return installed.get();
	}

	/**
	 * Recursively searches a given directory for any module manifest and extension 
	 * properties files that are in an installed state and converts them to an uninstalled
	 * state.
	 * 
	 * Specifically, the following will be renamed:
	 * <UL>
	 * <LI>Module.manifest to Module.manifest.uninstalled</LI>
	 * <LI>extension.properties = extension.properties.uninstalled</LI>
	 * </UL>
	 * 
	 * @param extension the extension to modify
	 * @return false if any renames fail
	 */
	public static boolean removeStateFiles(ExtensionDetails extension) {

		// Sanity check
		if (extension == null || extension.getInstallPath() == null ||
			extension.getInstallPath().isEmpty()) {
			return false;
		}

		boolean success = true;

		List<File> manifestFiles = new ArrayList<>();
		ExtensionUtils.findFilesWithName(new File(extension.getInstallPath()),
			ModuleUtilities.MANIFEST_FILE_NAME, manifestFiles);
		for (File f : manifestFiles) {
			if (f.exists()) {
				File newFile = new File(f.getAbsolutePath()
						.replace(ModuleUtilities.MANIFEST_FILE_NAME,
							ModuleUtilities.MANIFEST_FILE_NAME_UNINSTALLED));
				if (!f.renameTo(newFile)) {
					success = false;
				}
			}
		}

		List<File> propFiles = new ArrayList<>();
		ExtensionUtils.findFilesWithName(new File(extension.getInstallPath()),
			ExtensionUtils.PROPERTIES_FILE_NAME, propFiles);
		for (File f : propFiles) {
			if (f.exists()) {
				File newFile = new File(f.getAbsolutePath()
						.replace(ExtensionUtils.PROPERTIES_FILE_NAME,
							ExtensionUtils.PROPERTIES_FILE_NAME_UNINSTALLED));
				if (!f.renameTo(newFile)) {
					success = false;
				}
			}
		}

		return success;
	}

	/**
	 * Recursively searches a given directory for any module manifest and extension 
	 * properties files that are in an uninstalled state and restores them.
	 * 
	 * Specifically, the following will be renamed:
	 * <UL>
	 * <LI>Module.manifest.uninstalled to Module.manifest</LI>
	 * <LI>extension.properties.uninstalled = extension.properties</LI>
	 * </UL>
	 * 
	 * @param rootDir the directory to search
	 * @return false if any renames fail
	 */
	public static boolean restoreStateFiles(File rootDir) {

		boolean success = true;

		List<File> manifestFiles = new ArrayList<>();
		findFilesWithName(rootDir, ModuleUtilities.MANIFEST_FILE_NAME_UNINSTALLED, manifestFiles);
		for (File f : manifestFiles) {
			if (f.exists()) {
				File newFile = new File(f.getAbsolutePath()
						.replace(ModuleUtilities.MANIFEST_FILE_NAME_UNINSTALLED,
							ModuleUtilities.MANIFEST_FILE_NAME));
				if (!f.renameTo(newFile)) {
					success = false;
				}
			}
		}

		List<File> propFiles = new ArrayList<>();
		findFilesWithName(rootDir, PROPERTIES_FILE_NAME_UNINSTALLED, propFiles);
		for (File f : propFiles) {
			if (f.exists()) {
				File newFile = new File(f.getAbsolutePath()
						.replace(PROPERTIES_FILE_NAME_UNINSTALLED, PROPERTIES_FILE_NAME));
				if (!f.renameTo(newFile)) {
					success = false;
				}
			}
		}

		return success;
	}

	/**
	 * 
	 * @param root the starting directory to search recursively
	 * @param fileName the file name search for
	 * @param foundFiles list of all matching files
	 */
	public static void findFilesWithName(File root, String fileName, List<File> foundFiles) {

		if (root == null || foundFiles == null) {
			return;
		}

		if (root.isDirectory()) {
			File[] files = root.listFiles();
			if (files != null) {
				for (File file : files) {
					findFilesWithName(file, fileName, foundFiles);
				}
			}
		}
		else if (root.isFile() && root.getName().equals(fileName)) {
			foundFiles.add(root);
		}
	}

	/**
	 * Given a zip file, returns the {@link Properties} defined in the embedded extension.properties file. 
	 * 
	 * @param file the extension archive file
	 * @return the properties file, or null if doesn't exist
	 * @throws ExtensionException if there's a problem unpacking the zip file
	 */
	public static Properties getPropertiesFromArchive(File file) throws ExtensionException {

		try (ZipFile zipFile = new ZipFile(file)) {
			Enumeration<ZipArchiveEntry> zipEntries = zipFile.getEntries();
			while (zipEntries.hasMoreElements()) {
				ZipArchiveEntry entry = zipEntries.nextElement();
				if (entry.getName().endsWith(PROPERTIES_FILE_NAME)) {
					final InputStream propFile = zipFile.getInputStream(entry);
					Properties prop = new Properties();
					prop.load(propFile);
					return prop;
				}
			}

			return null;
		}
		catch (IOException e) {
			throw new ExtensionException(e.getMessage(), ExtensionExceptionType.ZIP_ERROR);
		}
	}

	/**
	 * Copies the given folder to the extension install location. Any existing folder at that
	 * location will be deleted.
	 * <p>
	 * Note: Any existing folder with the same name will be overwritten.
	 * 
	 * @param extension the extension folder
	 * @param monitor the task monitor
	 * @throws ExtensionException if the delete or copy fails
	 * @throws CancelledException if the user cancels the copy
	 */
	private static void copyToInstallationFolder(File extension, TaskMonitor monitor)
			throws ExtensionException, CancelledException {

		File newDir = null;
		try {
			newDir =
				new File(Application.getApplicationLayout().getExtensionInstallationDirs().get(0) +
					File.separator + extension.getName());
			FileUtilities.deleteDir(newDir, monitor);
			FileUtilities.copyDir(extension, newDir, monitor);
		}
		catch (IOException e) {
			throw new ExtensionException(e.getMessage(), ExtensionExceptionType.COPY_ERROR, newDir);
		}
	}

	/**
	 * Unpacks a given zip file to {@link ApplicationLayout#getExtensionInstallationDirs}. The 
	 * file permissions in the original zip will be retained.
	 * <p>
	 * Note: This method uses the Apache zip files since they keep track of permissions info; 
	 * the built-in java objects (e.g., ZipEntry) do not.
	 * 
	 * @param zipFile the zip file to unpack
	 * @param monitor the task monitor
	 * @throws ExtensionException if any part of the unzipping fails, or if the target location is invalid
	 * @throws CancelledException if the user cancels the unzip
	 * @throws IOException if error unzipping zip file
	 */
	private static void unzipToInstallationFolder(File zipFile, TaskMonitor monitor)
			throws ExtensionException, CancelledException, IOException {

		ApplicationLayout layout = Application.getApplicationLayout();

		if (!isZip(zipFile)) {
			throw new ExtensionException(zipFile.getAbsolutePath() + " is not a valid zip file",
				ExtensionExceptionType.ZIP_ERROR);
		}

		ResourceFile installDir = layout.getExtensionInstallationDirs().get(0);
		if (installDir == null || !installDir.exists()) {
			throw new ExtensionException(
				"Extension installation directory is not valid: " + installDir,
				ExtensionExceptionType.INVALID_INSTALL_LOCATION);
		}

		try (ZipFile zFile = new ZipFile(zipFile)) {

			Enumeration<ZipArchiveEntry> entries = zFile.getEntries();
			while (entries.hasMoreElements()) {

				ZipArchiveEntry entry = entries.nextElement();

				String filePath = installDir + File.separator + entry.getName();

				File file = new File(filePath);

				if (entry.isDirectory()) {
					file.mkdirs();
				}
				else {
					try (OutputStream outputStream =
						new BufferedOutputStream(new FileOutputStream(file))) {

						// Create the file at the new location...
						IOUtils.copy(zFile.getInputStream(entry), outputStream);

						// ...and update its permissions. But only continue if the zip
						// was created on a unix platform. If not we cannot use the posix
						// libraries to set permissions. 
						if (entry.getPlatform() == ZipArchiveEntry.PLATFORM_UNIX) {

							int mode = entry.getUnixMode();
							if (mode != 0) { // 0 indicates non-unix platform
								Set<PosixFilePermission> perms = getPermissions(mode);

								try {
									Files.setPosixFilePermissions(file.toPath(), perms);
								}
								catch (UnsupportedOperationException e) {
									// Need to catch this, as Windows does not support the
									// posix call. This is not an error, however, and should
									// just silently fail.
								}
							}
						}
					}
				}
			}
		}
	}

	/**
	 * Extracts information from a Java Properties file to create an {@link ExtensionDetails}
	 * object.
	 * 
	 * @param file the file to parse
	 * @return a new extension details object
	 */
	public static ExtensionDetails createExtensionDetailsFromPropertyFile(File file) {

		try {
			Properties props = new Properties();
			try (InputStream in = new FileInputStream(file.getAbsolutePath())) {
				props.load(in);
				return createExtensionDetailsFromProperties(props);
			}
		}
		catch (IOException e) {
			Msg.error(null, "Error processing extension properties for " + file.getAbsolutePath(),
				e);
			return null;
		}
	}

	/**
	 * Finds any extensions that have been installed since the last time a given tool was launched.
	 * 
	 * @param tool the tool to check
	 * @return set of new extensions
	 */
	public static Set<ExtensionDetails> getExtensionsInstalledSinceLastToolLaunch(PluginTool tool) {

		try {
			// Get set of all installed extensions. If there are none, just return.
			Set<ExtensionDetails> allExtensions = ExtensionUtils.getInstalledExtensions(false);
			if (allExtensions == null || allExtensions.isEmpty()) {
				return Collections.emptySet();
			}

			// Get the set of extensions that the tool already knows about. This information is stored 
			// in the tool preferences.
			Set<ExtensionDetails> knownExtensionsSet = new HashSet<>();
			DockingWindowManager dockingWindowManager =
				DockingWindowManager.getInstance(tool.getToolFrame());
			if (dockingWindowManager != null) {
				PreferenceState state =
					dockingWindowManager.getPreferenceState(GhidraTool.EXTENSIONS_PREFERENCE_NAME);
				if (state != null) {
					String[] knownExtensionNames =
						state.getStrings(GhidraTool.EXTENSIONS_PREFERENCE_NAME, new String[0]);

					Set<ExtensionDetails> installedExtensions =
						ExtensionUtils.getInstalledExtensions(false);

					for (String extensionName : knownExtensionNames) {
						for (ExtensionDetails ext : installedExtensions) {
							if (ext.getName().equals(extensionName)) {
								knownExtensionsSet.add(ext);
								break;
							}
						}
					}
				}
			}

			// Get the difference between the two sets.
			allExtensions.removeAll(knownExtensionsSet);

			return allExtensions;
		}
		catch (ExtensionException e) {
			Msg.error(tool, "Error retrieving installed extensions", e);
			return Collections.emptySet();
		}
	}

	/**
	 * Extracts information from a Java Properties file to create an {@link ExtensionDetails}
	 * object.
	 * 
	 * @param resourceFile the resource file file to parse
	 * @return a new extension details object
	 */
	public static ExtensionDetails createExtensionDetailsFromPropertyFile(
			ResourceFile resourceFile) {

		try (InputStream in = resourceFile.getInputStream()) {
			Properties props = new Properties();
			props.load(in);
			return createExtensionDetailsFromProperties(props);
		}
		catch (IOException e) {
			Msg.error(null,
				"Error processing extension properties for " + resourceFile.getAbsolutePath(),
				e);
			return null;
		}
	}

	/**
	 * Attempts to delete any extension directories that do not contain a Module.manifest 
	 * file. This indicates that the extension was slated to be uninstalled by the user.
	 * 
	 * @see #uninstall
	 */
	public static void cleanupUninstalledExtensions() {
		if (SystemUtilities.isInDevelopmentMode()) {
			return;
		}

		try {
			// 1. Get all extensions in the installation folder.
			Set<ExtensionDetails> installedExtensions = ExtensionUtils.getInstalledExtensions(true);

			// 2. For any that have a Module.manifest.uninstall, attempt to delete.
			for (ExtensionDetails ext : installedExtensions) {
				String installPath = ext.getInstallPath();
				File mm = new File(installPath, ModuleUtilities.MANIFEST_FILE_NAME_UNINSTALLED);
				if (mm.exists()) {
					boolean success = ExtensionUtils.uninstall(ext);
					if (!success) {
						Msg.error(null, "Error removing extension: " + ext.getInstallPath());
					}
				}
			}
		}
		catch (ExtensionException e) {
			Msg.error(null, "Error retrieving installed extensions", e);
		}
	}

	/**
	 * Extracts properties from a Java Properties file to create an {@link ExtensionDetails}
	 * object.
	 * 
	 * @param props the java properties object
	 * @return a new extension details object
	 */
	public static ExtensionDetails createExtensionDetailsFromProperties(Properties props) {

		String name = props.getProperty("name");
		String desc = props.getProperty("description");
		String author = props.getProperty("author");
		String date = props.getProperty("createdOn");
		String version = props.getProperty("version");

		return new ExtensionDetails(name, desc, author, date, version);
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
}
