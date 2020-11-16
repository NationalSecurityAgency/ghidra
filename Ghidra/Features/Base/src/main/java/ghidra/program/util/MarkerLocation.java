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
package ghidra.program.util;

import java.io.Serializable;
import java.util.Objects;

import ghidra.app.services.MarkerSet;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * Marker location in the tool navigation bars
 */
public class MarkerLocation implements Serializable {

	private int x;
	private int y;
	private Address addr;
	private MarkerSet markers;
	private final Program program;

	/**
	 * Construct a new MarkerLocation.
	 * @param markers marker manager service
	 * @param program program containing the address
	 * @param addr address of the location
	 * @param x x position of the popup point on the screen
	 * @param y y position of the popup point on the screen
	 */
	public MarkerLocation(MarkerSet markers, Program program, Address addr, int x, int y) {
		this.markers = markers;
		this.program = program;
		this.addr = addr;
		this.x = x;
		this.y = y;
	}

	/**
	 * Returns the program.
	 * 
	 * @return the program for this marker location
	 */
	public Program getProgram() {
		return program;
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
		return markers;
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((addr == null) ? 0 : addr.hashCode());
		result = prime * result + ((markers == null) ? 0 : markers.hashCode());
		result = prime * result + x;
		result = prime * result + y;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		MarkerLocation other = (MarkerLocation) obj;
		if (!Objects.equals(addr, other.addr)) {
			return false;
		}

		if (!Objects.equals(markers, other.markers)) {
			return false;
		}

		if (x != other.x) {
			return false;
		}
		if (y != other.y) {
			return false;
		}
		return true;
	}
}
