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
package ghidra.program.util;

import ghidra.util.classfinder.ExtensionPoint;

/**
 * AddressCorrelators that want to be discovered by version tracking should implement this interface.
 */
public interface DiscoverableAddressCorrelator extends AddressCorrelator, ExtensionPoint {
	// This interface has no methods. It simply provides an extension point for address correlators,
	// since we don't want all AddressCorrelator classes discovered. We do want classes that
	// extend this class to be found though.
}
