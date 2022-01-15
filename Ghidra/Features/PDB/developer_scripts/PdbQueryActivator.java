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
import org.osgi.framework.BundleContext;

import ghidra.app.plugin.core.osgi.GhidraBundleActivator;
import pdbquery.PdbFactory;

/**
 * Activator class for the PdbQuery bundle of scripts.  On "stop," calls method to close all PDBs.
 */
public class PdbQueryActivator extends GhidraBundleActivator {
	@Override
	protected void start(BundleContext bc, Object api) {
		// purposefully empty
	}

	@Override
	protected void stop(BundleContext bc, Object api) {
		PdbFactory.closeAllPdbs(null);
	}

}
