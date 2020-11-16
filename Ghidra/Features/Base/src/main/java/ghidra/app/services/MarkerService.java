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

import java.awt.Color;

import javax.swing.ImageIcon;
import javax.swing.event.ChangeListener;

import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * <p>
 * Service to manage navigation markers displayed around a scrollable window like the Listing.
 * The navigation bar displays the general location of markers for the entire view. The marker bar
 * displays a marker at each marked address visible within the view.
 * </p>
 * <p>
 * The interface defines priorities for display of markers in Marker Margin and colored bars in
 * Navigation Margin. The higher the priority, the more likely the marker/bar will be displayed on
 * the top. Areas will always be lower than marker priorities.
 * </p>
 * <a name="usage"></a> <u>Recommended Usage</u><br>
 * <u>Recommended Usage</u><br>
 * The service used to work independently of {@link Program}s.  In order to work effectively this
 * service has been changed to associate created markers with individual programs.  Thus, it is
 * up to the clients of this class perform lifecycle management of markers created by this
 * service.  For example, a client that creates a marker from
 * {@link #createAreaMarker(String, String, Program, int, boolean, boolean, boolean, Color)} should 
 * call {@link #removeMarker(MarkerSet, Program)} when the markers are no longer used, such as when
 * a program has become deactivated.  In this example usage markers are added and removed as the
 * user tabs through open programs.
 */
@ServiceInfo(defaultProvider = MarkerManagerPlugin.class, description = "Service to manage navigation markers displayed around a scrollable window.")
public interface MarkerService {

	/**
	 * Display priority for marking the selection.
	 */
	public final static int SELECTION_PRIORITY = 100;
	/**
	 * Display priority for marking the highlight.
	 */
	public final static int HIGHLIGHT_PRIORITY = 50;
	/**
	 * Display priority for marking a change set.
	 */
	public final static int CHANGE_PRIORITY = -50;
	/**
	 * Display priority for marking a change set for members in a group.
	 */
	public final static int GROUP_PRIORITY = -25;

	/**
	 * Display priority for marking the cursor location.
	 */
	public final static int CURSOR_PRIORITY = 200;

	/**
	 * Display priority for marking the cursor location.
	 */
	public final static int FUNCTION_COMPARE_CURSOR_PRIORITY = 49;

	/**
	 * Display priority for marking locations of search hits.
	 */
	public final static int SEARCH_PRIORITY = 75;
	/**
	 * Display priority for marking locations of breakpoints.
	 */
	public final static int BREAKPOINT_PRIORITY = 50;
	/**
	 * Display priority for bookmark locations.
	 */
	public final static int BOOKMARK_PRIORITY = 0;
	/**
	 * Display priority for marking locations where a property exists.
	 */
	public final static int PROPERTY_PRIORITY = 75;
	/**
	 * Display priority for marking locations where a program diff difference exists.
	 */
	public final static int DIFF_PRIORITY = 80;
	/**
	 * Display priority for marking references.
	 */
	public final static int REFERENCE_PRIORITY = -10;

	/**
	 * A group name for highlights.  This is intended to be used with
	 * {@link #setMarkerForGroup(String, MarkerSet, Program)} and
	 * {@link #removeMarkerForGroup(String, MarkerSet, Program)}
	 */
	public final static String HIGHLIGHT_GROUP = "HIGHLIGHT_GROUP";

	/**
	 * Create a Marker display which shows area type markers.
	 *
	 * @param name name of the navigation markers
	 * @param markerDescription description of the navigation markers
	 * @param program The program with which the created markers will be associated.
	 * @param priority to sort out what displays on top, higher is more likely to be on top
	 * @param showMarkers true indicates to show area markers (on the left side of the browser.)
	 * @param showNavigation true indicates to show area navigation markers (on the right side of the browser.)
	 * @param colorBackground if true, then the browser's background color will reflect the marker.
	 * @param color the color of marked areas.
	 * @return set of navigation markers
	 */
	public MarkerSet createAreaMarker(String name, String markerDescription, Program program,
			int priority, boolean showMarkers, boolean showNavigation, boolean colorBackground,
			Color color);

	/**
	 * Create a Marker display which shows area type markers.
	 *
	 * @param name name of the navigation markers
	 * @param markerDescription description of the navigation markers
	 * @param program The program with which the created markers will be associated.
	 * @param priority to sort out what displays on top, higher is more likely to be on top
	 * @param showMarkers true indicates to show area markers (on the left side of the browser.)
	 * @param showNavigation true indicates to show area navigation markers (on the right side of the browser.)
	 * @param colorBackground if true, then the browser's background color will reflect the marker.
	 * @param color the color of marked areas.
	 * @param isPreferred true indicates higher priority than all non-preferred MarkerSets
	 * @return set of navigation markers
	 */
	public MarkerSet createAreaMarker(String name, String markerDescription, Program program,
			int priority, boolean showMarkers, boolean showNavigation, boolean colorBackground,
			Color color, boolean isPreferred);

	/**
	 * Create a Marker display which shows point type markers.
	 *
	 * @param name name of the navigation markers
	 * @param markerDescription description of the navigation markers
	 * @param program The program with which the created markers will be associated.
	 * @param priority to sort out what displays on top, higher is more likely to be on top
	 * @param showMarkers true indicates to show area markers (on the left side of the browser.)
	 * @param showNavigation true indicates to show area navigation markers (on the right side of the browser.)
	 * @param colorBackground if true, then the browser's background color will reflect the marker.
	 * @param color the color of marked areas in navigation bar
	 * @param icon icon to display in marker bar
	 * @return set of navigation markers
	 */
	public MarkerSet createPointMarker(String name, String markerDescription, Program program,
			int priority, boolean showMarkers, boolean showNavigation, boolean colorBackground,
			Color color, ImageIcon icon);

	/**
	 * Create a Marker display which shows point type markers.
	 *
	 * @param name name of the navigation markers
	 * @param markerDescription description of the navigation markers
	 * @param program The program with which the created markers will be associated.
	 * @param priority to sort out what displays on top, higher is more likely to be on top
	 * @param showMarkers true indicates to show area markers (on the left side of the browser.)
	 * @param showNavigation true indicates to show area navigation markers (on the right side of the browser.)
	 * @param colorBackground if true, then the browser's background color will reflect the marker.
	 * @param color the color of marked areas in navigation bar
	 * @param icon icon to display in marker bar
	 * @param isPreferred is prioritized over non-preferred MarkersSets
	 * @return set of navigation markers
	 */
	public MarkerSet createPointMarker(String name, String markerDescription, Program program,
			int priority, boolean showMarkers, boolean showNavigation, boolean colorBackground,
			Color color, ImageIcon icon, boolean isPreferred);

	/**
	 * Remove the marker set
	 *
	 * @param markerSet marker set to be removed from navigation bars.
	 * @param program The program with which the markers are associated.
	 */
	public void removeMarker(MarkerSet markerSet, Program program);

	/**
	 * Return the marker set with the given name;
	 *
	 * @param name The name of the marker set for which to search
	 * @param program The program with which the created markers will be associated.
	 * @return the markerset with the given name;
	 */
	public MarkerSet getMarkerSet(String name, Program program);

	/**
	 * Sets a marker set for a given group name.  Any previous marker set associated with the
	 * given group name will be removed from this marker service.  This method is used to ensure
	 * that only one marker set is used at any time for a give group.
	 * @param groupName The name to associate the marker set with.
	 * @param markerSet The marker set to add to this service
	 * @param program The program with which the markers are associated.
	 * @see #removeMarkerForGroup(String, MarkerSet, Program)
	 */
	public void setMarkerForGroup(String groupName, MarkerSet markerSet, Program program);

	/**
	 * Removes a marker set for a given group name.  If the given marker set is not the marker
	 * set associated with the given group name, then no action will be taken.
	 * @param groupName The name associated the marker set with.
	 * @param markerSet The marker set to add to this service
	 * @param program The program with which the markers are associated.  May be null if the
	 *        marker is
	 * @see #setMarkerForGroup(String, MarkerSet, Program)
	 */
	public void removeMarkerForGroup(String groupName, MarkerSet markerSet, Program program);

	/**
	 * Returns the background color associated with the given address.  Each markerSet that supports
	 * background coloring is checked in priority order to see if it wants to specify a background
	 * color for the given address.
	 * @param address the address to check for a background color.
	 * @return the background color to use for that address or null if no markers contain that address.
	 */
	public Color getBackgroundColor(Address address);

	/**
	 * Returns the background color associated with the given program and address. Each markerSet
	 * that supports background coloring is checked in priority order to see if it wants to specify
	 * a background color for the given address.
	 * 
	 * If {@code program} is the current program, this is equivalent to
	 *  {@link #getBackgroundColor(Address)}.
	 * 
	 * @param program the program to check for a background color.
	 * @param address the address to check for a background color.
	 * @return the background color to use for that address or null if no markers contain that
	 *         address.
	 */
	public Color getBackgroundColor(Program program, Address address);

	/**
	 * Adds a change listener to be notified when markers are added/removed or the addresses in any
	 * current markerSets are changed
	 * 
	 * @param listener the listener
	 */
	public void addChangeListener(ChangeListener listener);

	/**
	 * Removes the given change listener from the list of listeners to be notified of changes
	 * 
	 * @param listener the listener
	 */
	public void removeChangeListener(ChangeListener listener);
}
