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
package ghidra.features.bsim.query.ingest;

import java.io.File;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.framework.*;
import ghidra.net.ApplicationTrustManagerFactory;
import ghidra.util.classfinder.ClassSearcher;

public class HeadlessBSimApplicationConfiguration extends ApplicationConfiguration {

	@Override
	protected void initializeApplication() {
		super.initializeApplication();

		// Locate certs if found (must be done before module initialization)
		locateCACertsFile();

		monitor.setMessage("Performing module initialization...");
		performModuleInitialization();

		monitor.setMessage("Done initializing");
	}

	/**
	 * Locate certs file within the Ghidra root directory.  If found this will be used
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
