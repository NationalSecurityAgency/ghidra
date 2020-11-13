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
package docking.widgets.fieldpanel.support;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * Records the current top of screen position of the viewer.
 */

public class ViewerPosition implements Serializable {

    private static final long serialVersionUID = 1;
 
	private BigInteger index;
	private int xOffset;
	private int yOffset;

	/**
	 * Construct a new viewer position with the given index, xOffset and yOffset.
	 * @param index the index of the layout displayed at the top of the screen.
	 * @param xOffset The horizontal scroll position (NOT CURRENTLY USED)
	 * @param yOffset the vertical position of the layout at the top of the screen.
	 * If the the layout is totally visible, then the yOffset will be 0. Otherwise,
	 * it will be &lt; 0 indicating that it begins above the top of the screen.
	 */
    public ViewerPosition(BigInteger index, int xOffset, int yOffset) {
		this.index = index;
		this.xOffset = xOffset;
		this.yOffset = yOffset;
    }

    public ViewerPosition(int index, int xOffset, int yOffset) {
    	this(BigInteger.valueOf(index), xOffset, yOffset);
    }
	/**
	 * Returns the index of the item at the top of the screen.
	 */
	public final int getIndexAsInt() {
		return index.intValue();
	}
	
	public final BigInteger getIndex() {
		return index;
	}
	
	/**
	 * Returns the horizontal scroll position.
	 */
	public final int getXOffset() {
		return xOffset;
	}

	/**
	 * Returns the y coordinate of the layout at the top of the screen.
	 */
	public final int getYOffset() {
		return yOffset;
	}

	/**
	 * 
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
    @Override
	public boolean equals(Object obj) {
        if (obj instanceof ViewerPosition) {
            ViewerPosition vp = (ViewerPosition)obj;
            return vp.index.equals(index) && vp.yOffset == yOffset;
        }
        return false;
    }
    /**
     * @see java.lang.Object#toString()
     */ 
    @Override
	public String toString() {
    	return "Index = " + index + ", xOffset = " + xOffset + 
				", yOffset = " + yOffset;
    } 

}
