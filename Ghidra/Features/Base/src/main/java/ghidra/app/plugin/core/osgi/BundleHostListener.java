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

	/**
	 * Invoked when a bundle is built.
	 * 
	 * @param bundle the bundle
	 * @param summary a summary of the build, or null if nothing changed (build returned false)
	 */
	default void bundleBuilt(GhidraBundle bundle, String summary) {
		//
	}

	/**
	 * Invoked when a bundle is enabled or disabled.
	 * 
	 * @param bundle the bundle
	 * @param newEnablement true if enabled, false if disabled
	 */
	default void bundleEnablementChange(GhidraBundle bundle, boolean newEnablement) {
		//
	}

	/**
	 * Invoked when a bundle is activated or deactivated.
	 * 
	 * @param bundle the bundle
	 * @param newActivation true if activated, false if deactivated
	 */
	default void bundleActivationChange(GhidraBundle bundle, boolean newActivation) {
		//
	}

	/**
	 * Invoked when a bundle is added to {@link BundleHost}
	 * 
	 * @param bundle the bundle
	 */
	default void bundleAdded(GhidraBundle bundle) {
		//
	}

	/**
	 * Invoked when a number of bundles is added at once. A listener should implement this method
	 * to avoid repeated invocation of {@link #bundleAdded} in quick succession. 
	 * 
	 * @param bundles the bundles
	 */
	default void bundlesAdded(Collection<GhidraBundle> bundles) {
		for (GhidraBundle bundle : bundles) {
			bundleAdded(bundle);
		}
	}

	/**
	 * Invoked when a bundle is removed from {@link BundleHost}
	 * 
	 * @param bundle the bundle
	 */
	default void bundleRemoved(GhidraBundle bundle) {
		//
	}

	/**
	 * Invoked when a number of bundles is removed at once. A listener should implement this method
	 * to avoid repeated invocation of {@link #bundleRemoved} in quick succession. 
	 * 
	 * @param bundles the bundles
	 */
	default void bundlesRemoved(Collection<GhidraBundle> bundles) {
		for (GhidraBundle bundle : bundles) {
			bundleRemoved(bundle);
		}
	}

	/**
	 * Invoked when {@link BundleHost} excepts during bundle activation/deactivation.
	 * 
	 * @param exception the exception thrown
	 */
	default void bundleException(GhidraBundleException exception) {
		//
	}

}
