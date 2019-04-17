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
package ghidra.program.util;

import ghidra.app.services.MarkerSet;
import ghidra.program.model.address.Address;

import java.io.Serializable;

/**
 * Object generated when pointer is over a particular marker in the browser
 * navigation bars.
 * 
 * 
 *
 */
public class MarkerLocation implements Serializable {
	
	private int x;
	private int y;
	private Address addr;
	private MarkerSet mgr;
    
	/**
	 * Construct a new MarkerLocation.
	 * @param mgr marker manager service
	 * @param addr address of the location
	 * @param x x position of the popup point on the screen
	 * @param y y position of the popup point on the screen
	 */
	public MarkerLocation(MarkerSet mgr, Address addr, int x, int y) {
		this.mgr = mgr;
		this.addr = addr;
		this.x = x;
		this.y = y;
	}

	/**
	 * Returns the address.
	 * 
	 * @return the address for this marker location
	 */
	public Address getAddr() {
		return addr;
	}

	/**
	 * Returns the Marker Manager.
	 * 
	 * @return the marker manager
	 */
	public MarkerSet getMarkerManager() {
		return mgr;
	}

	/**
	 * Returns the X screen location of the popup point.
	 * 
	 * @return the X coordinate for the screen location.
	 */
	public int getX() {
		return x;
	}

	/**
	 * Returns the Y screen location of the popup point.
	 * 
	 * @return the Y coordinate for the screen location.
	 */
	public int getY() {
		return y;
	}
    
    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
	@Override
    public boolean equals(Object obj) {
		if(obj == null) {
			return false;
		}
		if(this == obj) {
			return true;
		}
        if (getClass() != obj.getClass()) {
			return false;
		}
        MarkerLocation ml = (MarkerLocation) obj;
        if (addr.equals(ml.addr)) {
        	if (x == ml.x && y == ml.y) {
        		if (mgr == ml.mgr) {
        			return true;
        		}
        	}
        }
        return false;
	}
}
