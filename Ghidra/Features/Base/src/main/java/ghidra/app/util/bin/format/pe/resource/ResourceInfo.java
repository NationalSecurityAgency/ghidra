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
package ghidra.app.util.bin.format.pe.resource;

/**
 * A class to hold the information extracted from a 
 * resource data directory.
 * 
 * NOTE:
 * This class is simply a storage class created for 
 * parsing the PE header data structures.
 * It does not map back to a PE data data structure.
 */
public class ResourceInfo implements Comparable<ResourceInfo> {
    private int address;
    private String name;
    private int size;
    private int typeID;
    private int id;

    /**
     * Constructor.
     * @param address the adjusted address where the resource exists
     * @param name    the name of the resource
     * @param size    the size of the resource
     */
    public ResourceInfo(int address, String name, int size) {
        this.address   = address;
        this.name      = name;
        this.size      = size;
    }
	/**
	 * Returns the adjusted address where the resource exists.
	 * @return the adjusted address where the resource exists
	 */
    public int getAddress() {
        return address;
    }
	/**
	 * Returns the name of the resource.
	 * @return the name of the resource
	 */
    public String getName() {
        return name;
    }
	public void setName(String name) {
		this.name = name;
	}
    /**
     * Returns the size of the resource.
     * @return the size of the resource
     */
    public int getSize() {
        return size;
    }
    /**
     * Returns the ID of the resource.
     * @return the ID of the resource
     */
    public int getID() {
        return id;
    }
    public void setID(int id) {
		this.id = id;
	}
    /**
     * Returns the resource type ID.
     * For example, RT_CURSOR, RT_BITMAP, etc.
     * Returns -1 if this is a named resource.
     */
    public int getTypeID() {
		return typeID;
	}
    public void setTypeID(int typeID) {
		this.typeID = typeID;
	}

    @Override
    public String toString() {
    	return name+" - 0x"+Integer.toHexString(address);
    }

    public int compareTo(ResourceInfo that) {
    	return this.typeID - that.typeID;
    }
}
