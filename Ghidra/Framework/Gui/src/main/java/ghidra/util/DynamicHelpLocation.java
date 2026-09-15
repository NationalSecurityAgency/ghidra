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
package ghidra.util;

/**
 * An interface that can be added to the HelpService that signals the client has help that may  
 * change over time.  The Help system will query this class to see if there is help for the 
 * registered object at the time help is requested.   A client may register a static help location
 * and an instance of this class with the Help system.
 * <p>
 * This can be used by a component to change the help location based on focus or mouse interaction.
 * Typically a component will have one static help location.  However, if that component has help
 * for different areas within the component, then this interface allows that component to return 
 * any active help.   This is useful for components that perform custom painting of regions, in 
 * which case that region has no object to use for adding help to the help system.
 */
public interface DynamicHelpLocation {

	/**
	 * @return the current help location or null if there is currently no help for the client.
	 */
	public HelpLocation getActiveHelpLocation();
}
