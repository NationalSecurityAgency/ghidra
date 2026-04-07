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

import java.io.IOException;
import java.util.*;

import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;
import org.junit.Before;
import org.junit.Test;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.project.tool.testplugins.TestExtensionHello2Plugin;
import ghidra.framework.project.tool.testplugins.TestExtensionHelloPlugin;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.extensions.ExtensionUtils;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;

public class ExtensionManagerTest extends AbstractGhidraHeadedIntegrationTest {

	private ApplicationLayout appLayout;
	private FakeToolExtensionsEnabledState extensionsState;
	private ToolExtensionsStatusManager extensionManager;

	@Before
	public void setup() throws IOException {

		appLayout = Application.getApplicationLayout();

		ExtensionUtils.clearCache();
		deleteExtensionDirs();
		createExtensionDirs();

		extensionsState = new FakeToolExtensionsEnabledState();
		extensionManager = new ToolExtensionsStatusManager(extensionsState);
	}

	@Test
	public void testNewExtensionPromptsUser() throws Exception {

		// install new extension with a plugin
		extensionsState.addExtension("FooExtension", TestExtensionHelloPlugin.class);

		// call extension manager using xml with no knowledge of the new extension
		Element element = XmlUtilities.fromString("""
				<ROOT>
					<EXTENSIONS>
					</EXTENSIONS>
				</ROOT>
					""");
		extensionManager.restoreFromXml(element);

		// verify user is prompted to add new plugins
		extensionManager.checkForNewExtensions();
		waitForSwing();
		assertTrue(extensionsState.didPrompt());
	}

	@Test
	public void testKnownExtensionDoesNotPromptUser() throws Exception {

		// install extension with a plugin
		extensionsState.addExtension("FooExtension", TestExtensionHelloPlugin.class);

		// call extension manager with xml describing the extension
		//@formatter:off
		Element element = XmlUtilities.fromString(
	"""
	<ROOT>
		<EXTENSIONS>
			<EXTENSION NAME="FooExtension">
				<PLUGIN CLASS="ghidra.framework.project.tool.testplugins.TestExtensionHelloPlugin" />
			</EXTENSION>
		</EXTENSIONS>
	</ROOT>
		""");
		//@formatter:on
		extensionManager.restoreFromXml(element);

		// verify no prompt
		extensionManager.checkForNewExtensions();
		waitForSwing();
		assertFalse(extensionsState.didPrompt());
	}

	@Test
	public void testKnownExetension_OldStyleXml_UninstalledPlugins_PromptsUser() throws Exception {

		// 
		// Tests that old xml describing a known extension triggers a prompt.  The old style xml 
		// does not contain plugin names. Thus, we have no way of knowing if there are new plugins,
		// so we prompt. Tests support for tools with the old xml migrating to the new xml.  
		//

		// install extension with a plugin
		extensionsState.addExtension("FooExtension", TestExtensionHelloPlugin.class);

		// Call extension manager with old style xml describing the extension. This knows about the
		// extension, but not the plugins inside.
		Element element = XmlUtilities.fromString("""
				<ROOT>
					<EXTENSIONS>
						<EXTENSION NAME="FooExtension" />
					</EXTENSIONS>
				</ROOT>
					""");
		extensionManager.restoreFromXml(element);

		// verify user is prompted to add new plugins
		extensionManager.checkForNewExtensions();
		waitForSwing();
		assertTrue(extensionsState.didPrompt());
	}

	@Test
	public void testKnownExetension_OldStyleXml_AllPluginsInstalled_DoesNotPromptUser()
			throws Exception {

		// 
		// Given old style xml with knowledge of an extension, all extension plugins are installed,
		// the user is not prompted to install plugins. Tests support for tools with the old xml 
		// migrating to the new xml.  
		//

		// install extension with a plugin
		extensionsState.addExtension("FooExtension", TestExtensionHelloPlugin.class);

		// mark plugin as installed
		extensionsState.setInstalled(TestExtensionHelloPlugin.class);

		// Call extension manager with old style xml describing the extension. This knows about the
		// extension, but not the plugins inside.
		Element element = XmlUtilities.fromString("""
				<ROOT>
					<EXTENSIONS>
						<EXTENSION NAME="FooExtension" />
					</EXTENSIONS>
				</ROOT>
					""");
		extensionManager.restoreFromXml(element);

		// verify no prompt, since the plugins in the extension have already been installed
		extensionManager.checkForNewExtensions();
		waitForSwing();
		assertFalse(extensionsState.didPrompt());
	}

	@Test
	public void testKnownExtension_UpdatedWithNewPlugins_PromptsUser() throws Exception {

		//
		// Given an extension known in the xml, with a list of known plugins, and an updated version
		// of that extension is installed, the user is prompted to add plugins.
		//

		// install an extension with one known plugin and one new plugin
		extensionsState.addExtension("FooExtension", TestExtensionHelloPlugin.class,
			TestExtensionHello2Plugin.class);

		// call extension manager with new style xml that only knows about the original plugin
		//@formatter:off
		Element element = XmlUtilities.fromString(
	"""
	<ROOT>
		<EXTENSIONS>
			<EXTENSION NAME="FooExtension">
				<PLUGIN CLASS="ghidra.framework.project.tool.testplugins.TestExtensionHelloPlugin.class" />
			</EXTENSION>
		</EXTENSIONS>
	</ROOT>
	""");
		//@formatter:on
		extensionManager.restoreFromXml(element);

		// verify user is prompted to add new plugins
		extensionManager.checkForNewExtensions();
		waitForSwing();
		assertTrue(extensionsState.didPrompt());
	}

	@Test
	public void testSaveToXml_NoExtensions() throws Exception {

		Element rootElement = new Element("ROOT");
		extensionManager.saveToXml(rootElement);

		String expectedXml =
			"""
					<ROOT>
					    <EXTENSIONS />
					</ROOT>
						""".trim();
		String actualXml = toString(rootElement);

		assertEquals(expectedXml, actualXml);
	}

	private String toString(Element e) {
		XMLOutputter outputter = GenericXMLOutputter.getInstance();
		Format format = outputter.getFormat();
		format.setLineSeparator(System.lineSeparator());
		return outputter.outputString(e);
	}

	@Test
	public void testSaveToXml_OneExtension() throws Exception {

		extensionsState.addExtension("FooExtension", TestExtensionHelloPlugin.class);

		Element rootElement = new Element("ROOT");
		extensionManager.saveToXml(rootElement);

		//@formatter:off
		String expectedXml =
			"""
	<ROOT>
     <EXTENSIONS>
         <EXTENSION NAME="FooExtension">
             <PLUGIN CLASS="ghidra.framework.project.tool.testplugins.TestExtensionHelloPlugin" />
         </EXTENSION>
     </EXTENSIONS>
	</ROOT>
						""".trim();
		//@formatter:on
		String actualXml = toString(rootElement);

		assertEquals(expectedXml, actualXml);
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

	private class FakeToolExtensionsEnabledState implements ExtensionsEnabledState {

		private Map<String, Set<Class<?>>> extensions = new HashMap<>();
		private Set<Class<?>> installedPlugins = new HashSet<>();
		private boolean didPrompt = false;

		@Override
		public Map<String, Set<Class<?>>> getAllKnownExtensions() {
			return extensions;
		}

		@Override
		public void removeInstalledPlugins(Set<Class<?>> plugins) {
			plugins.removeAll(installedPlugins);
		}

		@Override
		public void propmtToConfigureNewPlugins(Set<Class<?>> plugins) {
			didPrompt = true;
		}

		void addExtension(String name, Class<?>... classes) {
			extensions.put(name, Set.of(classes));
		}

		boolean didPrompt() {
			return didPrompt;
		}

		void setInstalled(Class<TestExtensionHelloPlugin> c) {
			installedPlugins.add(c);
		}
	}

}
