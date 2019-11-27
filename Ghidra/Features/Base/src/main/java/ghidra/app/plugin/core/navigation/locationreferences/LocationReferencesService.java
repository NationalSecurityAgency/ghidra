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
package ghidra.app.plugin.core.navigation.locationreferences;

import ghidra.app.nav.Navigatable;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
 * A service that provides a GUI listing of all <b><i>from</i></b> locations that refer 
 * to a given <b><i>to</i></b> location.
 */
public interface LocationReferencesService {

	public static final String MENU_GROUP = "References";

	/**
	 * Returns the help location for help content that describes this service.
	 * @return the help location for help content that describes this service.
	 */
	public HelpLocation getHelpLocation();

	/**
	 * Shows a ComponentProvider containing a table of references that refer to the given
	 * location.
	 * @param location The location for which to show references.
	 * @param navigatable The navigatable in which the references should be shown
	 * @throws NullPointerException if <tt>location</tt> is null.
	 */
	public void showReferencesToLocation(ProgramLocation location, Navigatable navigatable);

}
