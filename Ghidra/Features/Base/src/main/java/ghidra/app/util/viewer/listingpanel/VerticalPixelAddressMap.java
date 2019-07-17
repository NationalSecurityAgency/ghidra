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
package ghidra.app.util.viewer.listingpanel;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;

public interface VerticalPixelAddressMap {

	/**
	 * Returns the Address of the first layout in this map
	 */
	public Address getStartAddress();

	/**
	 * Returns the index of the last layout in this map.
	 */
	public Address getEndAddress();

	/**
	 * Returns the number of layouts in this map.
	 */
	public int getNumLayouts();

	/**
	 * Returns the address of the i'th layout in this map.
	 * @param i the index into the local array of layouts
	 * @return the address of the i'th layout in this map.
	 */
	public Address getLayoutAddress(int i);

	/**
	 * Returns the y position of the top of the i'th layout.
	 * @param i the index of the layout.
	 */
	public int getBeginPosition(int i);

	/**
	 * Returns the y position of the bottom of the i'th layout.
	 * @param i the index of the layout.
	 */
	public int getEndPosition(int i);

	/**
	 * Returns pixel location to draw marker icon.
	 * @param i the index of the layout to be marked with an icon.
	 * @return the vertical pixel location at which to draw the icon.
	 */
	public int getMarkPosition(int i);

	/**
	 * Determines if the given layout index contains the primary field
	 * @param i the layout index to test.
	 * @return true if the layout contains the primary field.
	 */
	public boolean hasPrimaryField(int i);

	/**
	 * Finds the layout containing the given point.
	 * @param y the y coordinate of layout to be found.
	 */
	public int findLayoutAt(int y);

	/**
	 * Returns the address of the bottom of the i'th layout.  
	 * 
	 * <P>Note: this will return null if at the end of an overlay block. 
	 * 
	 * @param i the index of the layout
	 * @return the address of the bottom of the i'th layout
	 */
	public Address getLayoutEndAddress(int i);

	/**
	 * Gets the address set of this address map.
	 * @return the address set of this address map
	 */
	public AddressSetView getAddressSet();

}
