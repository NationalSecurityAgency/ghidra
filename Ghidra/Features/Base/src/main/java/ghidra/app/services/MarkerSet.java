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

import ghidra.program.model.address.*;

/**
 * Defines methods for working with a set of addresses that correspond to markers.
 * @see MarkerService
 */
public interface MarkerSet extends Comparable<MarkerSet> {

	/**
	 * Add a marker at the address
	 * @param addr the address
	 */
	public void add(Address addr);

	/**
	 * Add the range given the start and end of the range
	 * @param start the start address
	 * @param end the end address
	 */
	public void add(Address start, Address end);

	/**
	 * Add a marker across the address range
	 * @param range the addresses
	 */
	public void add(AddressRange range);

	/**
	 * Sets the AddressSetCollection to be used for this this marker set.
	 *  
	 * <p><strong>Warning!</strong> 
	 * Using this method will cause this MarkerSet to directly use the given AddressSetCollection.
	 * If the given AddressSetCollection is not an instance of ModifiableAddressSetCollection,
	 * then the markerSet methods that add and remove addresses will thrown an
	 * IllegalArgumentException.
	 * 
	 * @param set the addressSetCollection to use as this markerSet's addressSetCollection. 
	 */
	public void setAddressSetCollection(AddressSetCollection set);

	/**
	 * Clears the current set off addresses in this markerSet and adds in the addresses
	 * from the given AddressSet
	 * @param set the set of addresses to use in this marker set
	 */
	public void setAddressSet(AddressSetView set);

	/**
	 * Add a marker at each address in the given address set
	 * @param addrSet the addresses
	 */
	public void add(AddressSetView addrSet);

	/**
	 * Determine if this marker set contains the specified address
	 * @param addr address
	 * @return true if marker set contains addr
	 */
	public boolean contains(Address addr);

	/**
	 * Return the address set for this marker set
	 * @return the addresses
	 */
	public AddressSet getAddressSet();

	/**
	 * Clear any marker at the address
	 * @param addr the address
	 */
	public void clear(Address addr);

	/**
	 * Clear any marker across the address range
	 * @param range the addresses
	 */
	public void clear(AddressRange range);

	/**
	 * Remove the given range from the marker set
	 * @param start the start of the range to remove
	 * @param end the end of the range to remove
	 */
	public void clear(Address start, Address end);

	/**
	 * Clear any marker at each address in the address set
	 * @param addrSet the addresses
	 */
	public void clear(AddressSetView addrSet);

	/**
	 * Return the name of this MarkerSet
	 * @return the name
	 */
	public String getName();

	/**
	 * Clear all defined markers
	 */
	public void clearAll();

	/**
	 * Get display priority
	 * @return the priority
	 */
	public int getPriority();

	/**
	 * Gets whether this marker is in the preferred group when determining display priority.
	 * Typically point markers are in the preferred group and area markers are not.
	 * @return true if preferred
	 */
	public boolean isPreferred();

	/**
	 * Return true if this marker set is active
	 * @param state the state
	 */
	public void setActive(boolean state);

	/**
	 * Get the color for the marker
	 * @return the color
	 */
	public Color getMarkerColor();

	/**
	 * Set the color for the marker
	 * @param color marker color
	 */
	public void setMarkerColor(Color color);

	/**
	 * Set the marker manager listener to use for user interaction
	 * with markers owned by this manager.
	 * @param markerDescriptor the descriptor
	 */
	public void setMarkerDescriptor(MarkerDescriptor markerDescriptor);

	/**
	 * True if this marker manager displays in the right hand navigation bar
	 * @return true if this marker manager displays in the right hand navigation bar
	 */
	public boolean isDisplayedInNavigationBar();

	/**
	 * True if this marker manager displays in the left hand marker bar
	 * @return true if this marker manager displays in the left hand marker bar
	 */
	public boolean displayInMarkerBar();

	/**
	 * Returns true if this MarkerSet is coloring the background in the listing for locations
	 * contained in this MarkerSet
	 * @return true if coloring background
	 */
	public boolean isColoringBackground();

	/**
	 * Returns true if this MarkerSet is active.  Being "active" means that it is displayed
	 * in the listing
	 * @return true if active
	 */
	public boolean isActive();

	/**
	 * Sets whether or not the MarkerSet is coloring the background of areas in the listing
	 * contained in this MarkerSet.
	 * @param b true to color the background.
	 */
	public void setColoringBackground(boolean b);

	/**
	 * Returns the minimum Address in this MarkerSet;
	 * @return  the minimum Address in this MarkerSet;
	 */
	public Address getMinAddress();

	/**
	 * Returns the maximum Address in this MarkerSet;
	 * @return  the maximum Address in this MarkerSet;
	 */
	public Address getMaxAddress();

	/** 
	 * Returns true if any address in this MarkerSet is contained in the range defined by
	 * start and end.
	 * @param start the start address of the range to check for intersection.
	 * @param end the end address of the range to check for intersection.
	 * @return true if the set of addresses contained in this MarkerSet intersects the given range.
	 */
	public boolean intersects(Address start, Address end);

}
