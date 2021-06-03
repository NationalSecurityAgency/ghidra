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
package ghidra.app.plugin.core.colorizer;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;

import java.awt.Color;
import java.util.List;

/**
 * A service that allows the user to set the background color of the Listing at specific addresses.
 * <p>
 * The colors set here will appear in the listing and other plugins that use Listing components.
 */
public interface ColorizingService {

	/**
	 * Prompts the user to choose a color
	 * 
	 * @param suggestedColor The initial color to select; may be null
	 * @return the user chosen color or null if the user cancelled the operation
	 */
	public Color getColorFromUser(Color suggestedColor);

	/**
	 * Returns the most recently used color.   Returns null if the user has not chosen any colors
	 * by using this interface via {@link #getColorFromUser(Color)}.
	 * 
	 * @return the most recently used color; null if not set
	 */
	public Color getMostRecentColor();

	/**
	 * Gets the recently used colors.  These are the colors that users have picked in recent 
	 * sessions (up to a limit).  If not colors have been chosen via this interface, then the
	 * empty list is returned.
	 * 
	 * @return the recently used colors.
	 */
	public List<Color> getRecentColors();

	/**
	 * Sets the background color for the given address range.  This color data gets saved with
	 * the program.
	 * 
	 * @param min The start address to color
	 * @param max The end address of the given range to color
	 * @param color The color to apply
	 * 
	 * @see #clearBackgroundColor(Address, Address)
	 * @see #getBackgroundColor(Address)
	 */
	public void setBackgroundColor(Address min, Address max, Color color);

	/**
	 * Sets the background color for the given address range for the current program.  
	 * This color data gets saved with the program.  This color data gets saved with
	 * the program.
	 * 
	 * @param set The address at which the given color will be applied
	 * @param color The color to apply
	 * 
	 * @see #clearBackgroundColor(AddressSetView)
	 * @see #getBackgroundColor(Address)
	 */
	public void setBackgroundColor(AddressSetView set, Color color);

	/**
	 * Returns the color applied at the given address.
	 * 
	 * @param address The address to check
	 * @return The color applied at the given address; null if no color is set 
	 * 
	 * @see #setBackgroundColor(Address, Address, Color)
	 * @see #clearBackgroundColor(Address, Address)
	 */
	public Color getBackgroundColor(Address address);

	/**
	 * Returns a set of addresses where colors are applied.
	 * @return a set of addresses where colors are applied.
	 */
	public AddressSetView getAllBackgroundColorAddresses();

	/**
	 * Returns all addresses that have the given color applied.
	 * 
	 * @param color The applied color for which to check
	 * @return all addresses that have the given color applied.
	 */
	public AddressSetView getBackgroundColorAddresses(Color color);

	/**
	 * Clears any applied colors over the given address range.
	 * 
	 * @param min The start address of the given range to clear
	 * @param max The end address of the given range to clear
	 * 
	 * @see #setBackgroundColor(Address, Address, Color)
	 */
	public void clearBackgroundColor(Address min, Address max);

	/**
	 * Clears any applied colors over the given address set.
	 * 
	 * @param set The address set over which to clear any applied colors
	 * 
	 * @see #setBackgroundColor(AddressSetView, Color)
	 */
	public void clearBackgroundColor(AddressSetView set);

	/**
	 * Clears all background colors set on the current program.
	 * 
	 * @see #setBackgroundColor(Address, Address, Color)
	 * @see #clearBackgroundColor(Address, Address)
	 */
	public void clearAllBackgroundColors();
}
