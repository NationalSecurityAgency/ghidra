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
package ghidra.framework;

import java.io.File;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.GhidraClassLoader;
import ghidra.framework.preferences.Preferences;
import ghidra.net.ApplicationTrustManagerFactory;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;

public class HeadlessGhidraApplicationConfiguration extends ApplicationConfiguration {

	@Override
	protected void initializeApplication() {
		super.initializeApplication();

		// Now that preferences are accessible, finalize classpath by adding user plugin paths.
		// This must be done before class searching.
		addUserJarAndPluginPathsToClasspath();

		monitor.setMessage("Performing class searching...");
		performClassSearching();

		// Locate cacerts if found (must be done before module initialization)
		locateCACertsFile();

		monitor.setMessage("Performing module initialization...");
		performModuleInitialization();

		monitor.setMessage("Done initializing");
	}

	private void addUserJarAndPluginPathsToClasspath() {

		// In single jar mode, we probably didn't set the GhidraClassLoader on the command line,
		// so we can't support this.
		if (Application.inSingleJarMode()) {
			return;
		}

		// Make sure the Ghidra class loader is being used.  It might not be if we
		// get here from a test, for example.
		if (!(ClassLoader.getSystemClassLoader() instanceof GhidraClassLoader)) {
			return;
		}

		GhidraClassLoader loader = (GhidraClassLoader) ClassLoader.getSystemClassLoader();
		for (String path : Preferences.getPluginPaths()) {
			loader.addPath(path);
		}
	}

	private void performClassSearching() {

		// The class searcher searches the classpath, and Ghidra's classpath should be complete
		// for this configuration at this point.
		try {
			ClassSearcher.search(false, monitor);
		}
		catch (CancelledException e) {
			Msg.debug(this, "Class searching unexpectedly cancelled.");
		}
	}

	/**
	 * Locate cacerts file within the Ghidra root directory.  If found this will be used
	 * for initializing the ApplicationTrustManager used for SSL/PKI.
	 */
	private void locateCACertsFile() {
		for (ResourceFile appRoot : Application.getApplicationRootDirectories()) {
			File cacertsFile = new File(appRoot.getAbsolutePath(), "cacerts");
			if (cacertsFile.isFile()) {
				System.setProperty(ApplicationTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY,
					cacertsFile.getAbsolutePath());
				break;
			}
		}
	}

	private void performModuleInitialization() {
		List<ModuleInitializer> instances = ClassSearcher.getInstances(ModuleInitializer.class);
		for (ModuleInitializer initializer : instances) {
			monitor.setMessage("Initializing " + initializer.getName() + "...");
			initializer.run();
		}
	}
}
