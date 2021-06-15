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
package ghidra.util.extensions;

import static org.junit.Assert.*;

import java.io.*;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.plugintool.dialog.*;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;

/**
 * Tests for the {@link ExtensionUtils} class.
 *
 */
public class ExtensionUtilsTest extends AbstractDockingTest {

	// Name used in all tests when creating extensions.
	private String DEFAULT_EXT_NAME = "test";

	private ApplicationLayout gLayout;

	/*
	 * Create dummy archive and installation folders in the temp space that we can populate
	 * with extensions.
	 */
	@Before
	public void setup() throws IOException {

		gLayout = Application.getApplicationLayout();

		// Verify that the archive and install directories are empty (each test requires
		// we start with a clean slate). If they're not empty, CORRECT THE SITUATION.
		if (!checkCleanInstall()) {
			FileUtilities.deleteDir(gLayout.getExtensionArchiveDir().getFile(false));
			for (ResourceFile installDir : gLayout.getExtensionInstallationDirs()) {
				FileUtilities.deleteDir(installDir.getFile(false));
			}
		}

		createExtensionDirs();
	}

	/*
	 * Verifies that we can install an extension from a .zip file.
	 */
	@Test
	public void testInstallExtensionFromZip() throws IOException {

		// Create an extension and install it.
		ResourceFile rFile = new ResourceFile(createExtensionZip(DEFAULT_EXT_NAME));
		ExtensionUtils.install(rFile);

		// Verify there is something in the installation directory and it has the correct name
		checkDirtyInstall(DEFAULT_EXT_NAME);
	}

	/*
	 * Verifies that we can install an extension from a folder.
	 */
	@Test
	public void testInstallExtensionFromFolder() throws IOException {

		// Create an extension and install it.
		ResourceFile rFile = createExtensionFolder();
		ExtensionUtils.install(rFile);

		// Verify the extension is in the install folder and has the correct name
		checkDirtyInstall(DEFAULT_EXT_NAME);
	}

	/*
	 * Verifies that we can uninstall an extension.
	 */
	@Test
	public void testUninstallExtension() throws ExtensionException, IOException {

		// Create an extension and install it.
		ResourceFile rFile = new ResourceFile(createExtensionZip(DEFAULT_EXT_NAME));
		ExtensionUtils.install(rFile);

		checkDirtyInstall(DEFAULT_EXT_NAME);

		// Get the extension object that we need to uninstall - there will only
		// be one in the set.
		Set<ExtensionDetails> extensions = ExtensionUtils.getExtensions();
		assertTrue(extensions.size() == 1);

		ExtensionDetails ext = extensions.iterator().next();

		// Now uninstall it and verify we have a clean install folder
		ExtensionUtils.uninstall(ext);

		checkCleanInstall();
	}

	/*
	 * Verifies that trying to install an extension when there's already one with the same
	 * name installed will overwrite the existing and not throw an exception
	 *
	 * @throws Exception if there's a problem creating the temp extension folder
	 */
	@Test
	public void testInstallExtensionDuplicate() throws Exception {

		// Create an extension and install it.
		ResourceFile rFile = createExtensionFolder();
		ExtensionUtils.install(rFile);

		// Now create another extension with the same name and try
		// to install it.
		rFile = new ResourceFile(createExtensionZip(DEFAULT_EXT_NAME));

		boolean install = ExtensionUtils.install(rFile);
		assertEquals(install, true);
	}

	/*
	 * Verifies that we can properly recognize a valid .zip file.
	 */
	@Test
	public void testIsZip() throws IOException, ExtensionException {
		File zipFile = createExtensionZip(DEFAULT_EXT_NAME);
		assertTrue(ExtensionUtils.isZip(zipFile));
	}

	/*
	 * Verifies that we can identify when a .zip is a valid extension archive vs.
	 * just a regular old zip (ROZ).
	 * <p>
	 * Note: The presence of an extensions.properties file is the difference.
	 */
	@Test
	public void testIsExtension_Zip() throws IOException, ExtensionException {
		File zipFile1 = createExtensionZip(DEFAULT_EXT_NAME);
		assertTrue(ExtensionUtils.isExtension(new ResourceFile(zipFile1)));

		File zipFile2 = createNonExtensionZip(DEFAULT_EXT_NAME);
		assertTrue(!ExtensionUtils.isExtension(new ResourceFile(zipFile2)));
	}

	/*
	 * Verifies that we can recognize when a directory represents an extension.
	 * <p>
	 * Note: The presence of an extensions.properties file is the difference.
	 */
	@Test
	public void testIsExtension_Folder() throws IOException, ExtensionException {
		File extDir = createTempDirectory("TestExtFolder");
		new File(extDir, "extension.properties").createNewFile();
		assertTrue(ExtensionUtils.isExtension(new ResourceFile(extDir)));

		File nonExtDir = createTempDirectory("TestNonExtFolder");
		assertTrue(!ExtensionUtils.isExtension(new ResourceFile(nonExtDir)));
	}

	/*
	 * Verifies that the we can retrieve all unique extensions in the archive and
	 * install folders.
	 * <p>
	 * Note: This test eliminates the need to test the methods for retrieving archived vs. installed
	 * extensions individually.
	 */
	@Test
	public void testGetExtensions() throws ExtensionException, IOException {

		// First create an extension and install it, so we have 2 extensions: one in
		// the archive folder, and one in the install folder.
		File zipFile = createExtensionZip(DEFAULT_EXT_NAME);
		ExtensionUtils.install(new ResourceFile(zipFile));

		// Now getExtensions should give us exactly 1 extension in the return.
		Set<ExtensionDetails> extensions = ExtensionUtils.getExtensions();
		assertTrue(extensions.size() == 1);

		// Now add an archive extension with a different name and see if we get
		// 2 total extensions.
		createExtensionZip("Extension2");
		extensions = ExtensionUtils.getExtensions();
		assertTrue(extensions.size() == 2);

		// Now add a 3rd extension and install it. See if we have 3 total extensions.
		File extension3 = createExtensionZip("Extension3");
		ExtensionUtils.install(new ResourceFile(extension3));
		extensions = ExtensionUtils.getExtensions();
		assertTrue(extensions.size() == 3);
	}

	/*
	 * Catch-all test for verifying that 'bad' inputs to utility functions are
	 * handled properly.
	 */
	@Test
	public void testBadInputs() {

		boolean foundError = false;

		try {
			ExtensionUtils.uninstall((ExtensionDetails) null);
			ExtensionUtils.isExtension(null);
			ExtensionUtils.isZip(null);
			ExtensionUtils.install(new ResourceFile(new File("this/file/does/not/exist")));
			ExtensionUtils.install((ResourceFile) null);
			ExtensionUtils.install((ExtensionDetails) null, true);
		}
		catch (Exception e) {
			foundError = true;
		}

		assertTrue(foundError == false);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	/*
	 * Creates the extension archive and installation directories.
	 *
	 * @throws IOException if there's an error creating the directories
	 */
	private void createExtensionDirs() throws IOException {

		ResourceFile extensionDir = gLayout.getExtensionArchiveDir();
		if (!extensionDir.exists()) {
			if (!extensionDir.mkdir()) {
				throw new IOException("Failed to create extension archive directory for test");
			}
		}

		ResourceFile installDir = gLayout.getExtensionInstallationDirs().get(0);
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
		ResourceFile[] files = gLayout.getExtensionInstallationDirs().get(0).listFiles();
		return (files == null || files.length == 0);
	}

	/*
	 * Verifies that the installation folder is not empty and contains a folder
	 * with the given name.
	 *
	 * @param name the name of the installed extension
	 */
	private void checkDirtyInstall(String name) {
		ResourceFile[] files = gLayout.getExtensionInstallationDirs().get(0).listFiles();
		assertTrue(files.length >= 1);
		assertTrue(files[0].getName().equals(name));
	}

	/*
	 * Creates a valid extension in the archive folder. This extension is not a
	 * .zip, but a folder.
	 *
	 * @return the file representing the extension
	 * @throws IOException if there's an error creating the extension
	 */
	private ResourceFile createExtensionFolder() throws IOException {

		ResourceFile root = new ResourceFile(gLayout.getExtensionArchiveDir(), DEFAULT_EXT_NAME);
		root.mkdir();

		// Have to add a prop file so this will be recognized as an extension
		File propFile = new ResourceFile(root, "extension.properties").getFile(false);
		propFile.createNewFile();

		return root;
	}

	/*
	 * Create a generic zip that is a valid extension archive.
	 *
	 * @param zipName name of the zip to create
	 * @return a zip file
	 * @throws IOException if there's an error creating the zip
	 */
	private File createExtensionZip(String zipName) throws IOException {

		File f = new File(gLayout.getExtensionArchiveDir().getFile(false), zipName + ".zip");
		try (ZipOutputStream out = new ZipOutputStream(new FileOutputStream(f))) {
			out.putNextEntry(new ZipEntry(zipName + "/"));
			out.putNextEntry(new ZipEntry(zipName + "/extension.properties"));

			StringBuilder sb = new StringBuilder();
			sb.append("name:" + zipName);
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

		File f = new File(gLayout.getExtensionArchiveDir().getFile(false), zipName + ".zip");
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
}
