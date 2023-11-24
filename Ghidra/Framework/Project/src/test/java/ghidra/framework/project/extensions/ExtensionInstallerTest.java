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

import static org.junit.Assert.*;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.Before;
import org.junit.Test;

import docking.DialogComponentProvider;
import docking.test.AbstractDockingTest;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.extensions.ExtensionDetails;
import ghidra.util.extensions.ExtensionUtils;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;
import utility.function.ExceptionalCallback;
import utility.module.ModuleUtilities;

/**
 * Tests for the {@link ExtensionInstaller} class.
 */
public class ExtensionInstallerTest extends AbstractDockingTest {

	private static final String BUILD_FOLDER_NAME = "TestExtensionParentDir";
	private static final String TEST_EXT_NAME = "test";

	private ApplicationLayout appLayout;

	/*
	 * Create dummy archive and installation folders in the temp space that we can populate
	 * with extensions.
	 */
	@Before
	public void setup() throws IOException {

		// to see tracing; must set the 'console' appender to trace to see these
		// Configurator.setLevel("ghidra.framework.project.extensions", Level.TRACE);

		setErrorGUIEnabled(false);

		// clear static caching of extensions
		ExtensionUtils.clearCache();

		appLayout = Application.getApplicationLayout();

		FileUtilities.deleteDir(appLayout.getExtensionArchiveDir().getFile(false));
		for (ResourceFile installDir : appLayout.getExtensionInstallationDirs()) {
			FileUtilities.deleteDir(installDir.getFile(false));
		}

		createExtensionDirs();
	}

	private static <E extends Exception> void errorsExpected(ExceptionalCallback<E> c)
			throws Exception {
		try {
			setErrorsExpected(true);
			c.call();
		}
		finally {
			setErrorsExpected(false);
		}
	}

	/*
	 * Verifies that we can install an extension from a .zip file.
	 */
	@Test
	public void testInstallExtensionFromZip() throws IOException {

		// Create an extension and install it.
		File file = createExtensionZip(TEST_EXT_NAME);
		ExtensionInstaller.install(file);

		// Verify there is something in the installation directory and it has the correct name
		checkExtensionInstalledInFilesystem(TEST_EXT_NAME);
	}

	/*
	 * Verifies that we can install an extension from a folder.
	 */
	@Test
	public void testInstallArchiveExtensionFromFolder() throws IOException {

		// Create an extension and install it.
		File file = createExtensionFolderInArchiveDir();
		ExtensionInstaller.install(file);

		// Verify the extension is in the install folder and has the correct name
		checkExtensionInstalledInFilesystem(TEST_EXT_NAME);
	}

	@Test
	public void testIsExtension_Zip_ValidZip() throws IOException {
		File zipFile1 = createExtensionZip(TEST_EXT_NAME);
		assertTrue(ExtensionUtils.isExtension(zipFile1));
	}

	@Test
	public void testIsExtension_Zip_InvalidZip() throws Exception {

		errorsExpected(() -> {
			File zipFile2 = createNonExtensionZip(TEST_EXT_NAME);
			assertFalse(ExtensionUtils.isExtension(zipFile2));
		});
	}

	/*
	 * Verifies that we can recognize when a directory represents an extension.
	 * <p>
	 * Note: The presence of an extensions.properties file is the difference.
	 */
	@Test
	public void testIsExtension_Folder() throws Exception {
		File extDir = createTempDirectory("TestExtFolder");
		new File(extDir, "extension.properties").createNewFile();
		assertTrue(ExtensionUtils.isExtension(extDir));

		errorsExpected(() -> {
			File nonExtDir = createTempDirectory("TestNonExtFolder");
			assertFalse(ExtensionUtils.isExtension(nonExtDir));
		});
	}

	@Test
	public void testBadInputs() throws Exception {
		errorsExpected(() -> {
			assertFalse(ExtensionInstaller.install(new File("this/file/does/not/exist")));
			assertFalse(ExtensionInstaller.install(null));
			assertFalse(ExtensionInstaller.installExtensionFromArchive(null));
		});
	}

	@Test
	public void testInstallExtensionFromArchive() throws Exception {
		File zipFile = createExtensionZip(TEST_EXT_NAME);
		ExtensionDetails extension = new TestExtensionDetails(TEST_EXT_NAME);
		extension.setArchivePath(zipFile.getAbsolutePath());
		String ghidraVersion = Application.getApplicationVersion();
		extension.setVersion(ghidraVersion);
		assertTrue(ExtensionInstaller.installExtensionFromArchive(extension));
	}

	@Test
	public void testInstallExtensionFromZipArchive_VersionMismatch_Cancel() throws Exception {

		File zipFile = createExtensionZip(TEST_EXT_NAME, "v2");
		ExtensionDetails extension = new TestExtensionDetails(TEST_EXT_NAME);
		extension.setArchivePath(zipFile.getAbsolutePath());

		AtomicBoolean didInstall = new AtomicBoolean();
		runSwingLater(() -> {
			didInstall.set(ExtensionInstaller.installExtensionFromArchive(extension));
		});

		DialogComponentProvider confirmDialog =
			waitForDialogComponent("Extension Version Mismatch");
		pressButtonByText(confirmDialog, "Cancel");

		assertFalse(didInstall.get());
	}

	@Test
	public void testInstallExtensionFromZipArchive_VersionMismatch_Continue() throws Exception {

		File zipFile = createExtensionZip(TEST_EXT_NAME, "v2");
		ExtensionDetails extension = new TestExtensionDetails(TEST_EXT_NAME);
		extension.setArchivePath(zipFile.getAbsolutePath());

		AtomicBoolean didInstall = new AtomicBoolean();
		runSwingLater(() -> {
			didInstall.set(ExtensionInstaller.installExtensionFromArchive(extension));
		});

		DialogComponentProvider confirmDialog =
			waitForDialogComponent("Extension Version Mismatch");
		pressButtonByText(confirmDialog, "Install Anyway");

		assertFalse(didInstall.get());
	}

	@Test
	public void testInstallExtensionFromZipArchive_NullVersion() throws Exception {

		File zipFile = createExtensionZip(TEST_EXT_NAME, null);
		ExtensionDetails extension = new TestExtensionDetails(TEST_EXT_NAME);
		extension.setVersion(null);
		extension.setArchivePath(zipFile.getAbsolutePath());

		AtomicBoolean didInstall = new AtomicBoolean();
		runSwingLater(() -> {
			didInstall.set(ExtensionInstaller.installExtensionFromArchive(extension));
		});

		DialogComponentProvider confirmDialog =
			waitForDialogComponent("Extension Version Mismatch");
		pressButtonByText(confirmDialog, "Cancel");

		assertFalse(didInstall.get());
	}

	@Test
	public void testMarkForUninstall_ClearMark() throws Exception {

		File externalFolder = createExternalExtensionInFolder();
		assertTrue(ExtensionInstaller.install(externalFolder));

		ExtensionDetails extension = assertExtensionInstalled(TEST_EXT_NAME);

		extension.markForUninstall();
		checkMarkForUninstall(extension);
		assertFalse(extension.isInstalled());

		// Also test that we can clear the uninstall marker
		extension.clearMarkForUninstall();
		assertExtensionInstalled(TEST_EXT_NAME);
	}

	@Test
	public void testCleanupUninstalledExtions_WithExtensionMarkedForUninstall() throws Exception {

		File externalFolder = createExternalExtensionInFolder();
		assertTrue(ExtensionInstaller.install(externalFolder));

		ExtensionDetails extension = assertExtensionInstalled(TEST_EXT_NAME);

		extension.markForUninstall();
		checkMarkForUninstall(extension);
		assertFalse(extension.isInstalled());

		// Also test that we can clear the uninstall marker
		ExtensionUtils.initializeExtensions();
		checkCleanInstall();
	}

	@Test
	public void testCleanupUninstalledExtions_SomeExtensionMarkedForUninstall() throws Exception {

		List<File> extensionFolders = createTwoExternalExtensionsInFolder();
		assertTrue(ExtensionInstaller.install(extensionFolders.get(0)));
		assertTrue(ExtensionInstaller.install(extensionFolders.get(1)));

		Set<ExtensionDetails> extensions = ExtensionUtils.getInstalledExtensions();
		assertEquals(extensions.size(), 2);

		Iterator<ExtensionDetails> it = extensions.iterator();
		ExtensionDetails extensionToRemove = it.next();
		ExtensionDetails extensionToKeep = it.next();
		assertTrue(extensionToRemove.isInstalled());

		extensionToRemove.markForUninstall();
		checkMarkForUninstall(extensionToRemove);
		assertFalse(extensionToRemove.isInstalled());

		// Also test that we can clear the uninstall marker
		ExtensionUtils.initializeExtensions();
		assertExtensionInstalled(extensionToKeep.getName());
	}

	@Test
	public void testCleanupUninstalledExtions_NoExtensionsMarkedForUninstall() throws Exception {

		File externalFolder = createExternalExtensionInFolder();
		assertTrue(ExtensionInstaller.install(externalFolder));
		assertExtensionInstalled(TEST_EXT_NAME);

		// This should not uninstall any extensions
		ExtensionUtils.initializeExtensions();
		assertExtensionInstalled(TEST_EXT_NAME);
	}

//=================================================================================================
// Edge Cases
//=================================================================================================

	@Test
	public void testInstallingNewExtension_SameName_NewVersion() throws Exception {

		// install extension Foo with Ghidra version
		File buildFolder = createTempDirectory(BUILD_FOLDER_NAME);
		String appVersion = Application.getApplicationVersion();
		File extensionFolder =
			doCreateExternalExtensionInFolder(buildFolder, TEST_EXT_NAME, appVersion);
		assertTrue(ExtensionInstaller.install(extensionFolder));

		Set<ExtensionDetails> extensions = ExtensionUtils.getInstalledExtensions();
		assertEquals(extensions.size(), 1);
		ExtensionDetails installedExtension = extensions.iterator().next();

		// create another extension Foo v2
		File buildFolder2 = createTempDirectory("TestExtensionParentDir2");
		String newVersion = "v2";
		File extensionFolder2 =
			doCreateExternalExtensionInFolder(buildFolder2, TEST_EXT_NAME, newVersion);

		AtomicBoolean didInstall = new AtomicBoolean();
		runSwingLater(() -> {
			didInstall.set(ExtensionInstaller.install(extensionFolder2));
		});

		DialogComponentProvider confirmDialog = waitForDialogComponent("Duplicate Extension");
		pressButtonByText(confirmDialog, "Remove Existing");

		waitForSwing();
		assertFalse(didInstall.get());
		checkMarkForUninstall(installedExtension);

		// run again after choosing to replace the installed extension
		ExtensionUtils.initializeExtensions(); // removed marked extensions
		checkCleanInstall();

		runSwingLater(() -> {
			didInstall.set(ExtensionInstaller.install(extensionFolder2));
		});

		// no longer an installed extension conflict; now we have a version mismatch
		confirmDialog = waitForDialogComponent("Extension Version Mismatch");
		pressButtonByText(confirmDialog, "Install Anyway");

		waitFor(didInstall);
		assertExtensionInstalled(TEST_EXT_NAME, newVersion);
		assertExtensionNotInstalled(TEST_EXT_NAME, appVersion);
	}

	@Test
	public void testInstallingNewExtension_SameName_NewVersion_Cancel() throws Exception {

		// install extension Foo with Ghidra version
		File buildFolder = createTempDirectory(BUILD_FOLDER_NAME);
		String appVersion = Application.getApplicationVersion();
		File extensionFolder =
			doCreateExternalExtensionInFolder(buildFolder, TEST_EXT_NAME, appVersion);
		assertTrue(ExtensionInstaller.install(extensionFolder));

		// create another extension Foo v2
		File buildFolder2 = createTempDirectory("TestExtensionParentDir2");
		String newVersion = "v2";
		File extensionFolder2 =
			doCreateExternalExtensionInFolder(buildFolder2, TEST_EXT_NAME, newVersion);

		AtomicBoolean didInstall = new AtomicBoolean();
		runSwingLater(() -> {
			didInstall.set(ExtensionInstaller.install(extensionFolder2));
		});

		DialogComponentProvider confirmDialog = waitForDialogComponent("Duplicate Extension");
		pressButtonByText(confirmDialog, "Cancel");
		waitForSwing();

		assertExtensionInstalled(TEST_EXT_NAME, appVersion);
		assertExtensionNotInstalled(TEST_EXT_NAME, newVersion);
	}

	@Test
	public void testInstallingNewExtension_SameName_SaveVersion() throws Exception {

		// install extension Foo with Ghidra version
		File buildFolder = createTempDirectory(BUILD_FOLDER_NAME);
		String appVersion = Application.getApplicationVersion();
		File extensionFolder =
			doCreateExternalExtensionInFolder(buildFolder, TEST_EXT_NAME, appVersion);
		assertTrue(ExtensionInstaller.install(extensionFolder));

		Set<ExtensionDetails> extensions = ExtensionUtils.getInstalledExtensions();
		assertEquals(extensions.size(), 1);
		ExtensionDetails installedExtension = extensions.iterator().next();

		// create another extension Foo v2
		File buildFolder2 = createTempDirectory("TestExtensionParentDir2");
		String newVersion = appVersion;
		File extensionFolder2 =
			doCreateExternalExtensionInFolder(buildFolder2, TEST_EXT_NAME, newVersion);

		AtomicBoolean didInstall = new AtomicBoolean();
		runSwingLater(() -> {
			didInstall.set(ExtensionInstaller.install(extensionFolder2));
		});

		DialogComponentProvider confirmDialog = waitForDialogComponent("Duplicate Extension");
		pressButtonByText(confirmDialog, "Remove Existing");

		waitForSwing();
		assertFalse(didInstall.get());
		checkMarkForUninstall(installedExtension);

		// run again after choosing to replace the installed extension
		ExtensionUtils.initializeExtensions(); // removed marked extensions
		checkCleanInstall();

		runSwingLater(() -> {
			didInstall.set(ExtensionInstaller.install(extensionFolder2));
		});

		waitFor(didInstall);
		assertExtensionInstalled(TEST_EXT_NAME, newVersion);
		assertEquals(1, ExtensionUtils.getInstalledExtensions().size());
	}

	@Test
	public void testInstallingNewExtension_FromZip_ZipHasMultipleExtensions() throws Exception {

		// test that we can detect when a zip has more than one extension inside (as determined
		// by multiple properties files 1 level down from the root with different folder names

		/*
		 	Create a zip file that looks something like this:

		 	/
		 	 	{Extension Name 1}/
					extension.properties

				{Extension Name 2}/
					extension.properties

		 */

		errorsExpected(() -> {
			File zipFile = createZipWithMultipleExtensions();
			assertFalse(ExtensionInstaller.install(zipFile));
		});
	}

	@Test
	public void testInstallThenUninstallThenReinstallWhenExtensionNameDoesntMatchFolder()
			throws Exception {

		// This tests a previous failure case where an extension could not be reinstalled if its
		// name did not match the folder it was installed into.  This could happen because the code
		// that installed the extension did not match the code to clear the 'mark for uninstall'
		// condition.

		String nameProperty = "ExtensionNamedFoo";
		File externalFolder = createExtensionWithMismatchingNamePropertyString(nameProperty);
		assertTrue(ExtensionInstaller.install(externalFolder));

		ExtensionDetails extension = assertExtensionInstalled(nameProperty);

		extension.markForUninstall();
		checkMarkForUninstall(extension);
		assertFalse(extension.isInstalled());

		// Also test that we can clear the uninstall marker
		extension.clearMarkForUninstall();
		assertExtensionInstalled(nameProperty);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private ExtensionDetails assertExtensionInstalled(String name) {
		Set<ExtensionDetails> extensions = ExtensionUtils.getInstalledExtensions();
		Optional<ExtensionDetails> match =
			extensions.stream().filter(e -> e.getName().equals(name)).findFirst();
		assertTrue("No extension installed named '" + name + "'", match.isPresent());
		ExtensionDetails extension = match.get();
		assertTrue(extension.isInstalled());
		return extension;
	}

	private ExtensionDetails assertExtensionInstalled(String name, String version) {
		Set<ExtensionDetails> extensions = ExtensionUtils.getInstalledExtensions();
		Optional<ExtensionDetails> match =
			extensions.stream().filter(e -> e.getName().equals(name)).findFirst();
		assertTrue("No extension installed named '" + name + "'", match.isPresent());
		ExtensionDetails extension = match.get();
		assertEquals(version, extension.getVersion());
		assertTrue(extension.isInstalled());
		return extension;
	}

	private void assertExtensionNotInstalled(String name, String version) {
		Set<ExtensionDetails> extensions = ExtensionUtils.getInstalledExtensions();
		Optional<ExtensionDetails> match = extensions.stream()
				.filter(e -> e.getName().equals(name) && e.getVersion().equals(version))
				.findFirst();
		assertFalse("Extension should not be installed: '" + name + "'", match.isPresent());
	}

	/*
	 * Creates the extension archive and installation directories.
	 *
	 * @throws IOException if there's an error creating the directories
	 */
	private void createExtensionDirs() throws IOException {

		ResourceFile extensionDir = appLayout.getExtensionArchiveDir();
		if (!extensionDir.exists()) {
			if (!extensionDir.mkdir()) {
				throw new IOException("Failed to create extension archive directory for test");
			}
		}

		ResourceFile installDir = appLayout.getExtensionInstallationDirs().get(0);
		if (!installDir.exists()) {
			if (!installDir.mkdir()) {
				throw new IOException("Failed to create extension installation directory for test");
			}
		}
	}

	/*
	 * Verifies that the installation folder is empty.
	 */
	private boolean checkCleanInstall() {
		ResourceFile[] files = appLayout.getExtensionInstallationDirs().get(0).listFiles();
		return (files == null || files.length == 0);
	}

	/*
	 * Verifies that the installation folder is not empty and contains a folder with the given name.
	 *
	 * @param name the name of the installed extension
	 */
	private void checkExtensionInstalledInFilesystem(String name) {
		ResourceFile[] files = appLayout.getExtensionInstallationDirs().get(0).listFiles();
		assertTrue(files.length >= 1);
		assertEquals(files[0].getName(), name);
	}

	private void checkMarkForUninstall(ExtensionDetails extension) {
		checkMarkForUninstall(extension.getInstallDir());
	}

	private void checkMarkForUninstall(File extensionDir) {
		File propertiesFile = new File(extensionDir, ExtensionUtils.PROPERTIES_FILE_NAME);
		assertFalse(propertiesFile.exists());
		File markedPropertiesFile =
			new File(extensionDir, ExtensionUtils.PROPERTIES_FILE_NAME_UNINSTALLED);
		assertTrue(markedPropertiesFile.exists());
	}

	/*
	 * Creates a valid extension in the archive folder. This extension is not a .zip, but a folder.
	 *
	 * @return the file representing the extension
	 * @throws IOException if there's an error creating the extension
	 */
	private File createExtensionFolderInArchiveDir() throws IOException {

		ResourceFile root = new ResourceFile(appLayout.getExtensionArchiveDir(), TEST_EXT_NAME);
		root.mkdir();

		// Have to add a prop file so this will be recognized as an extension
		File propFile = new ResourceFile(root, "extension.properties").getFile(false);
		assertTrue(propFile.createNewFile());

		Properties props = new Properties();
		props.put("name", TEST_EXT_NAME);
		props.put("description", "This is a description for " + TEST_EXT_NAME);
		props.put("author", "First Last");
		props.put("createdOn", new SimpleDateFormat("MM/dd/yyyy").format(new Date()));
		props.put("version", Application.getApplicationVersion());

		try (OutputStream os = new FileOutputStream(propFile)) {
			props.store(os, null);
		}

		return root.getFile(false);
	}

	private File createExternalExtensionInFolder() throws Exception {
		File externalFolder = createTempDirectory(BUILD_FOLDER_NAME);
		return doCreateExternalExtensionInFolder(externalFolder, TEST_EXT_NAME);
	}

	private File doCreateExternalExtensionInFolder(File externalFolder, String extensionName)
			throws Exception {
		String version = Application.getApplicationVersion();
		return doCreateExternalExtensionInFolder(externalFolder, extensionName, version);
	}

	private File doCreateExternalExtensionInFolder(File externalFolder, String extensionName,
			String version) throws Exception {
		return doCreateExternalExtensionInFolder(externalFolder, extensionName, extensionName,
			version);
	}

	private File createExtensionWithMismatchingNamePropertyString(String nameProperty)
			throws Exception {

		File externalFolder = createTempDirectory(BUILD_FOLDER_NAME);
		String version = Application.getApplicationVersion();
		return doCreateExternalExtensionInFolder(externalFolder, TEST_EXT_NAME, nameProperty,
			version);
	}

	private File doCreateExternalExtensionInFolder(File externalFolder, String extensionName,
			String nameProperty, String version) throws Exception {
		ResourceFile root = new ResourceFile(new ResourceFile(externalFolder), extensionName);
		root.mkdir();

		// Have to add a prop file so this will be recognized as an extension
		File propFile = new ResourceFile(root, "extension.properties").getFile(false);
		assertTrue(propFile.createNewFile());
		Properties props = new Properties();
		props.put("name", nameProperty);
		props.put("description", "This is a description for " + extensionName);
		props.put("author", "First Last");
		props.put("createdOn", new SimpleDateFormat("MM/dd/yyyy").format(new Date()));
		props.put("version", version);

		try (OutputStream os = new FileOutputStream(propFile)) {
			props.store(os, null);
		}

		File manifest = new ResourceFile(root, ModuleUtilities.MANIFEST_FILE_NAME).getFile(false);
		manifest.createNewFile();

		return root.getFile(false);
	}

	private List<File> createTwoExternalExtensionsInFolder() throws Exception {
		File externalFolder = createTempDirectory(BUILD_FOLDER_NAME);
		File extension1 = doCreateExternalExtensionInFolder(externalFolder, TEST_EXT_NAME);
		File extension2 = doCreateExternalExtensionInFolder(externalFolder, TEST_EXT_NAME + "Two");
		return List.of(extension1, extension2);
	}

	/*
	 * Create a generic zip that is a valid extension archive.
	 *
	 * @param zipName name of the zip to create
	 * @return a zip file
	 * @throws IOException if there's an error creating the zip
	 */
	private File createExtensionZip(String zipName) throws IOException {

		File externalFolder = createTempDirectory(BUILD_FOLDER_NAME);
		String version = Application.getApplicationVersion();
		File f = new File(externalFolder, zipName + ".zip");
		try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(f))) {
			out.putNextEntry(new ZipEntry(zipName + "/"));
			out.putNextEntry(new ZipEntry(zipName + "/extension.properties"));

			StringBuilder sb = new StringBuilder();
			sb.append("name:").append(zipName).append('\n');
			sb.append("version:").append(version).append('\n');
			byte[] data = sb.toString().getBytes();
			out.write(data, 0, data.length);
			out.closeEntry();
		}

		return f;
	}

	private File createExtensionZip(String zipName, String version) throws IOException {

		File externalFolder = createTempDirectory(BUILD_FOLDER_NAME);
		File f = new File(externalFolder, zipName + ".zip");
		try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(f))) {
			out.putNextEntry(new ZipEntry(zipName + "/"));
			out.putNextEntry(new ZipEntry(zipName + "/extension.properties"));

			StringBuilder sb = new StringBuilder();
			sb.append("name:").append(zipName).append('\n');
			sb.append("version:").append(version).append('\n');
			byte[] data = sb.toString().getBytes();
			out.write(data, 0, data.length);
			out.closeEntry();
		}

		return f;
	}

	private File createZipWithMultipleExtensions() throws IOException {

		String zipName1 = "Foo";
		String zipName2 = "Bar";
		File externalFolder = createTempDirectory(BUILD_FOLDER_NAME);
		File f = new File(externalFolder, "MultiExtension.zip");
		try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(f))) {
			out.putNextEntry(new ZipEntry(zipName1 + "/"));
			out.putNextEntry(new ZipEntry(zipName1 + "/extension.properties"));

			out.putNextEntry(new ZipEntry(zipName2 + "/"));
			out.putNextEntry(new ZipEntry(zipName2 + "/extension.properties"));

			StringBuilder sb = new StringBuilder();
			sb.append("name:MultiExtension");
			byte[] data = sb.toString().getBytes();
			out.write(data, 0, data.length);
			out.closeEntry();
		}

		return f;
	}

	/*
	 * Create a generic zip that is NOT a valid extension archive (because it doesn't
	 * have an extension.properties file).
	 *
	 * @param zipName name of the zip to create
	 * @return a zip file
	 * @throws IOException if there's an error creating the zip
	 */
	private File createNonExtensionZip(String zipName) throws IOException {

		File f = new File(appLayout.getExtensionArchiveDir().getFile(false), zipName + ".zip");
		try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(f))) {
			out.putNextEntry(new ZipEntry(zipName + "/"));
			out.putNextEntry(new ZipEntry(zipName + "/randomFile.txt"));

			StringBuilder sb = new StringBuilder();
			sb.append("name:" + zipName);
			byte[] data = sb.toString().getBytes();
			out.write(data, 0, data.length);
			out.closeEntry();
		}

		return f;
	}

	private class TestExtensionDetails extends ExtensionDetails {
		TestExtensionDetails(String name) {
			super(name, "Description", "Author", "01/01/01", "1.0");
		}
	}
}
