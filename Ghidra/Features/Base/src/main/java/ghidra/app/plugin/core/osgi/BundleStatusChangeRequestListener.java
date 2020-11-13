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

/**
 * events thrown by BundleStatus component when buttons are clicked
 */
public interface BundleStatusChangeRequestListener {

	/**
	 * Invoked when the user requests that a bundle is enabled/disabled.
	 * 
	 * @param status the current status
	 * @param newValue true if enabled, false if disabled
	 */
	default void bundleEnablementChangeRequest(BundleStatus status, boolean newValue) {
		//
	}

	/**
	 * Invoked when the user requests that a bundle is activated/deactivated.
	 * 
	 * @param status the current status
	 * @param newValue true if activated, false if deactivated
	 */
	default void bundleActivationChangeRequest(BundleStatus status, boolean newValue) {
		//
	}

}
