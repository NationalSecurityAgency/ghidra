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
package ghidra.app.plugin.core.osgi;

import java.util.Collection;

/**
 * Listener for OSGi framework events.
 */
public interface BundleHostListener {

	default void bundleBuilt(GhidraBundle gbundle, String summary) {
		//
	}

	default void bundleEnablementChange(GhidraBundle gbundle, boolean newEnablement) {
		//
	}

	default void bundleActivationChange(GhidraBundle gbundle, boolean newActivation) {
		//
	}

	default void bundleAdded(GhidraBundle gbundle) {
		//
	}

	default void bundlesAdded(Collection<GhidraBundle> gbundles) {
		for (GhidraBundle gbundle : gbundles) {
			bundleAdded(gbundle);
		}
	}

	default void bundleRemoved(GhidraBundle gbundle) {
		//
	}

	default void bundlesRemoved(Collection<GhidraBundle> gbundles) {
		for (GhidraBundle gbundle : gbundles) {
			bundleRemoved(gbundle);
		}
	}

	default void bundleException(GhidraBundleException gbe) {
		//
	}

}
