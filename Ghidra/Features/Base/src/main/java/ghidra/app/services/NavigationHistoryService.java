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
package ghidra.app.services;

import java.util.List;

import ghidra.app.nav.LocationMemento;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.framework.plugintool.ServiceInfo;

/**
 * The ToolStateHistoryService maintains a stack of locations that the user 
 * has visited via a navigation plugin.  
 * It provides methods querying and manipulating this list. 
 */
@ServiceInfo(defaultProvider = NavigationHistoryPlugin.class, description = "Maintains a history of tool states")
public interface NavigationHistoryService {

	/**
	 * Positions the current location to the next location in the history list.
	 * If there is no "next" location, the history list remains unchanged.
	 * @param navigatable the navigatable to be navigated
	 */
	public void next(Navigatable navigatable);

	/**
	 * Positions the "current" location to the previous location in the history list.
	 * If there is no "previous" location, the history list remains unchanged.
	 * @param navigatable the navigatable to be navigated
	 */
	public void previous(Navigatable navigatable);

	/** 
	 * Navigates to the given location in the "next" list.  If the location is not in the list, then
	 * nothing will happen.
	 * 
	 * @param navigatable the navigatable to be navigated
	 * @param location The location within the "next" list to which to go 
	 */
	public void next(Navigatable navigatable, LocationMemento location);

	/** 
	 * Navigates to the given location in the "previous" list.  If the location is not in 
	 * the list, then nothing will happen
	 * 
	 * @param navigatable the navigatable to be navigated
	 * @param location The location within the "previous" list to which to go. 
	 */
	public void previous(Navigatable navigatable, LocationMemento location);

	/**
	 * Positions the "current" location to the next location which is in a different function
	 * from current one or previous non-code location.
	 * If we are not inside any function, performs like "next".
	 * @param navigatable the navigatable to be navigated
	 */
	public void nextFunction(Navigatable navigatable);

	/**
	 * Positions the "previous" location to the next location which is in a different function
	 * from current one or previous non-code location.
	 * If we are not inside any function, performs like "next".
	 * @param navigatable the navigatable to be navigated
	 */
	public void previousFunction(Navigatable navigatable);

	/**
	 * Returns the LocationMemento objects in the "previous" list
	 * 
	 * @param navigatable the navigatable to be navigated
	 * @return the LocationMemento objects in the "previous" list
	 */
	public List<LocationMemento> getPreviousLocations(Navigatable navigatable);

	/**
	 * Returns the LocationMemento objects in the "next" list
	 * 
	 * @param navigatable the navigatable to be navigated
	 * @return the LocationMemento objects in the "next" list
	 */
	public List<LocationMemento> getNextLocations(Navigatable navigatable);

	/**
	 * Returns true if there is a valid "next" location in the history list.
	 * 
	 * @param navigatable the navigatable to be navigated
	 * @return true if there is a "next" location
	 */
	public boolean hasNext(Navigatable navigatable);

	/**
	 * Returns true if there is a valid "previous" location in the history list
	 * 
	 * @param navigatable the navigatable to be navigated
	 * @return true if there is a "previous" location
	 */
	public boolean hasPrevious(Navigatable navigatable);

	/**
	 * Returns true if there is a valid "next" function location in the history list
	 * @param navigatable Navigatable object we are looking at
	 * @return true if there is a valid "next" function location 
	 */
	public boolean hasNextFunction(Navigatable navigatable);

	/**
	 * Returns true if there is a valid "previous" function location in the history list
	 * @param navigatable Navigatable object we are looking at
	 * @return true if there is a valid "previous" function location 
	 */
	public boolean hasPreviousFunction(Navigatable navigatable);

	/**
	 * Adds the given locationMomento to the list of previous locations.  Clears the list
	 * of next locations.
	 * 
	 * @param navigatable the navigatable to be navigated
	 */
	public void addNewLocation(Navigatable navigatable);

	/**
	 * Removes all visited locations from the history list
	 * 
	 * @param navigatable the navigatable to be navigated
	 */
	public void clear(Navigatable navigatable);
}
