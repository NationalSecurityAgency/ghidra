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
package ghidra.framework.project.tool;

import static org.junit.Assert.*;

import java.awt.Window;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.jar.*;

import javax.tools.*;

import org.junit.Before;
import org.junit.Test;

import docking.DialogComponentProvider;
import generic.jar.ResourceFile;
import ghidra.GhidraClassLoader;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.project.extensions.ExtensionInstaller;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.extensions.ExtensionDetails;
import ghidra.util.extensions.ExtensionUtils;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

public class ExtensionManagerIntegrationTest extends AbstractGhidraHeadedIntegrationTest {

	private ApplicationLayout appLayout;

	@Override
	protected ApplicationConfiguration createApplicationConfiguration() {

		// This is a workaround to get the ClassSearcher to use the custom extensions class loader, 
		// which is required, since the standard class loader's classpath was set by the time this
		// code gets run.  Without this, the standard class loader cannot find our new extension.
		// The classpath is normally managed by the GhidraLauncher in a non-test environment.
		System.setProperty(GhidraClassLoader.ENABLE_RESTRICTED_EXTENSIONS_PROPERTY,
			Boolean.TRUE.toString());

		return super.createApplicationConfiguration();
	}

	@Before
	public void setup() throws IOException {

		appLayout = Application.getApplicationLayout();

		ExtensionUtils.clearCache();
		deleteExtensionDirs();
		createExtensionDirs();
	}

	@Test
	public void testNewExtensionPromptsUser() throws Exception {

		//
		// Create a new extension with a plugin
		//
		File srcExtensionFolder = createExternalExtensionInFolder();
		assertTrue(ExtensionInstaller.install(srcExtensionFolder));

		//
		// Update classpath the extension (this is normally done by the GhidraLauncher)
		//
		Set<ExtensionDetails> extensions = ExtensionUtils.getInstalledExtensions();
		assertEquals(1, extensions.size());
		ExtensionDetails extension = CollectionUtils.get(extensions);
		File extensionFolder = extension.getInstallDir();
		String jarFile = extensionFolder + File.separator + "lib/TestHelloWorldExtension.jar";

		String cp = System.getProperty("java.class.path");
		System.setProperty("java.class.path", cp + File.pathSeparator + jarFile);

		setInstanceField("hasSearched", ClassSearcher.class, false);
		ClassSearcher.search(TaskMonitor.DUMMY);

		//
		// Launch the tool and verify the user is prompted to load the new plugins
		//
		String title = "New Plugins Found!";
		launchTool(title);

		DialogComponentProvider dialog = waitForDialogComponent(title);
		pressButtonByText(dialog, "Yes", false);

		DialogComponentProvider installerDialog = waitForDialogComponent(title);
		close(installerDialog);
	}

	private void launchTool(String title) throws Exception {

		/*
		 	Launching the tool with new extensions will show a modal dialog.  Tool startup is slow
		 	enough that we can't use the normal wait mechanism, as it will timeout.
		 */
		TestEnv env = new TestEnv();
		runSwing(() -> {
			env.launchDefaultTool();
		}, false);

		int total = 0;
		int max = 20_000;
		int sleepyTime = 250;
		while (total < max) {
			sleep(sleepyTime);
			total += sleepyTime;
			Window w = getWindow(title);
			if (w != null) {
				return;
			}
		}
	}

	private File createExternalExtensionInFolder() throws Exception {
		File externalFolder = createTempDirectory("TestExtensionParentDir");
		return doCreateExternalExtensionInFolder(externalFolder, "TextExtension");
	}

	private File doCreateExternalExtensionInFolder(File externalFolder, String extensionName)
			throws Exception {

		String version = Application.getApplicationVersion();

		ResourceFile root = new ResourceFile(new ResourceFile(externalFolder), extensionName);
		assertTrue(FileUtilities.mkdirs(root.getFile(false)));

		// Have to add a prop file so this will be recognized as an extension
		File propFile = new ResourceFile(root, "extension.properties").getFile(false);
		assertTrue(propFile.createNewFile());
		Properties props = new Properties();
		props.put("name", extensionName);
		props.put("description", "This is a description for " + extensionName);
		props.put("author", "First Last");
		props.put("createdOn", new SimpleDateFormat("MM/dd/yyyy").format(new Date()));
		props.put("version", version);

		try (OutputStream os = new FileOutputStream(propFile)) {
			props.store(os, null);
		}

		File manifest = new ResourceFile(root, ModuleUtilities.MANIFEST_FILE_NAME).getFile(false);
		manifest.createNewFile();

		createJarWithPluginClass(root);

		Msg.debug(this, "extension dir: " + root);

		return root.getFile(false);
	}

	private void createJarWithPluginClass(ResourceFile root) throws Exception {

		ResourceFile lib = new ResourceFile(root, "lib");
		assertTrue(FileUtilities.mkdirs(lib.getFile(false)));

		String jarName = "TestHelloWorldExtension.jar";

		File jarFile = createExtensionLibJar(jarName);

		Msg.debug(this, "wrote jar: " + jarFile);

		File libFile = new File(lib.getFile(false), jarName);
		FileUtilities.copyFile(jarFile, libFile, false, TaskMonitor.DUMMY);
	}

	private File createExtensionLibJar(String jarName) throws Exception {

		Manifest manifest = new Manifest();
		manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");

		File tempFile = createTempFileForTest();
		File tempParent = tempFile.getParentFile();
		File jarFile = new File(tempParent, jarName);
		tempFile.renameTo(jarFile);

		FileOutputStream fos = new FileOutputStream(jarFile);
		JarOutputStream jos = new JarOutputStream(fos, manifest);

		File classDir = compileExtensionPlugin();
		Msg.debug(this, "class file: " + classDir);
		File[] files = classDir.listFiles((dir, name) -> name.endsWith(".class"));
		File classFile = files[0];

		JarEntry dirEntry = new JarEntry(classDir.getName() + "/");
		jos.putNextEntry(dirEntry);
		jos.closeEntry();

		JarEntry fileEntry = new JarEntry(dirEntry.getName() + classFile.getName());
		jos.putNextEntry(fileEntry);

		try (FileInputStream fis = new FileInputStream(classFile)) {
			byte[] buffer = new byte[1024];
			int bytesRead;
			while ((bytesRead = fis.read(buffer)) != -1) {
				jos.write(buffer, 0, bytesRead);
			}
		}
		jos.closeEntry();

		jos.close();
		fos.close();

		Msg.debug(this, "jar file: " + jarFile);

		return jarFile;
	}

	private File compileExtensionPlugin() throws Exception {

		// 1. Get the system Java compiler
		JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
		if (compiler == null) {
			System.err.println("JDK not found. Make sure you are running a JDK, not a JRE.");
			fail();
			return null;
		}

		File sourceFile = File.createTempFile("tmp", ".tmp");
		File dir = sourceFile.getParentFile();
		File packageDir = new File(dir, "testplugin");
		packageDir.mkdirs();
		File packagedSource = new File(packageDir, "TestHelloWorldPlugin.java");

		FileUtilities.writeStringToFile(packagedSource,
			"""
					package testplugin;

					import ghidra.app.ExamplesPluginPackage;
					import ghidra.app.plugin.PluginCategoryNames;
					import ghidra.framework.plugintool.*;
					import ghidra.framework.plugintool.util.PluginStatus;

					//@formatter:off
					@PluginInfo(
						status = PluginStatus.RELEASED,
						packageName = ExamplesPluginPackage.NAME,
						category = PluginCategoryNames.EXAMPLES,
						shortDescription = "Displays 'Hello World'",
						description = "Test plugin"
					)
					//@formatter:on
					public class TestHelloWorldPlugin extends Plugin {
						public TestHelloWorldPlugin(PluginTool tool) {
							super(tool);
						}
					}
					      """);

		DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();

		StandardJavaFileManager fileManager =
			compiler.getStandardFileManager(diagnostics, null, null);

		Iterable<? extends JavaFileObject> compilationUnits =
			fileManager.getJavaFileObjects(packagedSource);

		// 5. Create a compilation task
		JavaCompiler.CompilationTask task = compiler.getTask(
			null,           // output writer (uses System.err if null)
			fileManager,    // file manager (uses standard if null)
			diagnostics,    // diagnostic listener (uses System.err if null)
			null,           // options (pass null for no options)
			null,           // classes for annotation processing
			compilationUnits // source files
		);

		// 6. Execute the compilation task
		boolean success = task.call();

		// 7. Process the diagnostics
		if (success) {
			System.out.println("Compilation successful.");
		}
		else {
			System.out.println("Compilation failed.");
			for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
				System.out.println(diagnostic.getKind() + ": " + diagnostic.getMessage(null) +
					" (Line: " + diagnostic.getLineNumber() + ")");
			}
		}

		fileManager.close();

		return packageDir;
	}

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

	private void deleteExtensionDirs() {
		FileUtilities.deleteDir(appLayout.getExtensionArchiveDir().getFile(false));
		for (ResourceFile installDir : appLayout.getExtensionInstallationDirs()) {
			FileUtilities.deleteDir(installDir.getFile(false));
		}
	}
}
