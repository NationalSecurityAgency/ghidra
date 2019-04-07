/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util;

import ghidra.framework.plugintool.ServiceProvider;

// Interface for objects that represent a generic location.

public interface Location {

	/**
	 * Returns a displayable representation of this location.
	 * @return a displayable representation of this location.
	 */
	String getStringRepresentation();

	/**
	 * Returns a description for the location.  This should probably describe the significance of the
	 * location.  For example, if this location is from an Issue, then what is its relationship to the
	 * issue.
	 * @return a descrition for the location.
	 */
	String getDescription();

	/**
	 * Will attempt to navigate to the location as appropriate.  For example, it may use the goto service
	 * to navigate the code browser to a progam and and address.  Or it could launch a browser and
	 * display a web page.
	 * @param provider a service provider that this location can use to find a service to help with
	 * navigation.
	 * @return true if the navigation was successful, false otherwise.
	 */
	boolean go(ServiceProvider provider);

}
