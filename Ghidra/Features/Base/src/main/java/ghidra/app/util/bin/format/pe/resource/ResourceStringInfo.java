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
package ghidra.app.util.bin.format.pe.resource;

/**
 * A class to hold the information extracted from a 
 * resource data directory.
 * 
 * NOTE:
 * This class is simply a storage class created for 
 * parsing the PE header data structures.
 * It does not map back to a PE data data structure.
 * 
 * 
 */
public class ResourceStringInfo {
    private int address;
    private String string;
    private int length;
    /**
     * Constructor.
     * @param address the adjusted address where the resource exists
     * @param string the resource string
     * @param length the length of the resource
     */
	public ResourceStringInfo(int address, String string, int length) {
        this.address = address;
        this.string = string;
        this.length = length;
	}
	/**
	 * Returns the adjusted address where the resource exists.
	 * @return the adjusted address where the resource exists
	 */
    public int getAddress() {
        return address;
    }
    /**
     * Returns the resource string.
     * @return the resource string
     */
    public String getString() {
        return string;
    }
    /**
     * Returns the length of the resource.
     * @return the length of the resource
     */
    public int getLength() {
        return length;
    }
}
