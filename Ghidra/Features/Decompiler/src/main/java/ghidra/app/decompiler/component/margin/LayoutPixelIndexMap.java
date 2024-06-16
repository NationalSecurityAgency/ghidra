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
package ghidra.app.decompiler.component.margin;

import java.math.BigInteger;

import docking.widgets.fieldpanel.LayoutModel;
import ghidra.program.model.listing.Program;

/**
 * A mapping from pixel coordinate to layout index
 * 
 * <p>
 * At the moment, the only implementation provides a map from vertical position to layout. While
 * this does not have to be the case, the documentation will presume the y coordinate.
 */
public interface LayoutPixelIndexMap {
	/**
	 * Get the top of the layout with the given index
	 * 
	 * <p>
	 * Gets the minimum y coordinate of any pixel occupied by the layout having the given index. In
	 * essence, this maps from layout index to vertical position, relative to the main panel's
	 * viewport. This accounts for scrolling and non-uniform height among the layouts.
	 * 
	 * @param index the index of the layout
	 * @return the top of the layout, relative to the main panel's viewport
	 */
	int getPixel(BigInteger index);

	/**
	 * Get the index of the layout at the given position
	 * 
	 * <p>
	 * Get the index of the layout occupying the line of pixels in the main panel having the given y
	 * coordinate. In essence, this maps from vertical position, relative to the main panel's
	 * viewport, to layout index. This accounts for scrolling and non-uniform height among the
	 * layouts.
	 * 
	 * @implNote Clients should avoid frequent calls to this method. Even though it can be
	 *           implemented easily in log time, an invocation for every pixel or line of pixels
	 *           painted could still be unnecessarily expensive. It should only be necessary to call
	 *           this once or twice per repaint. See
	 *           {@link DecompilerMarginProvider#setProgram(Program, LayoutModel, LayoutPixelIndexMap)}.
	 * 
	 * @param pixel the vertical position of the pixel, relative to the main panel's viewport
	 * @return the index of the layout
	 */
	BigInteger getIndex(int pixel);
}
