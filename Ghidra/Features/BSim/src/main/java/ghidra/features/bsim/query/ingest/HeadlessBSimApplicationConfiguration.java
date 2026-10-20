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

import org.apache.commons.lang3.StringUtils;

import generic.jar.ResourceFile;
import ghidra.framework.*;
import ghidra.framework.remote.GhidraObjectInputFilter;
import ghidra.net.DefaultTrustManagerFactory;
import ghidra.util.Msg;
import ghidra.util.classfinder.ClassSearcher;

public class HeadlessBSimApplicationConfiguration extends ApplicationConfiguration {

	@Override
	protected void initializeApplication() {
		super.initializeApplication();

		try {
			// Install client-side deserialization filters (data/*.serial.filter)
			GhidraObjectInputFilter.configureClientSerialFilter();

			// Locate certs if found (must be done before module initialization)
			locateCACertsFile();

			monitor.setMessage("Performing module initialization...");
			performModuleInitialization();
		}
		catch (Throwable t) {
			Msg.error(this, "Ghidra encountered a severe error during initialization", t);
			System.exit(-1);
		}

		monitor.setMessage("Done initializing");
	}

	/**
	 * Locate 'cacerts' file within the Ghidra root directory if 'ghidra.cacerts' property has not
	 * already been specified.  If found this will be used to establish the property which will be 
	 * used by {@link DefaultTrustManagerFactory}.
	 */
	private void locateCACertsFile() {
		
		String cacertsPath = System.getProperty(DefaultTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY);
		if (!StringUtils.isBlank(cacertsPath)) {
			return; // property will be used by DefaultTrustManagerFactory
		}
		
		for (ResourceFile appRoot : Application.getApplicationRootDirectories()) {
			File cacertsFile = new File(appRoot.getAbsolutePath(), "cacerts");
			if (cacertsFile.isFile()) {
				System.setProperty(DefaultTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY,
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
