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
package ghidra.app.util.bin.format.ne;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.util.Conv;

/**
 * An implementation of the TTYPEINFO structure.
 * 
 * 
 */
public class ResourceType {
	//0x00 is not defined...?
	/**Constant indicating cursor resource type.*/
	public final static short RT_CURSOR = 0x01;
	/**Constant indicating bitmap resource type.*/
	public final static short RT_BITMAP = 0x02;
	/**Constant indicating icon resource type.*/
	public final static short RT_ICON = 0x03;
	/**Constant indicating menu resource type.*/
	public final static short RT_MENU = 0x04;
	/**Constant indicating dialog resource type.*/
	public final static short RT_DIALOG = 0x05;
	/**Constant indicating string resource type.*/
	public final static short RT_STRING = 0x06;
	/**Constant indicating font directory resource type.*/
	public final static short RT_FONTDIR = 0x07;
	/**Constant indicating font resource type.*/
	public final static short RT_FONT = 0x08;
	/**Constant indicating an accelerator resource type.*/
	public final static short RT_ACCELERATOR = 0x09;
	/**Constant indicating RC data resource type.*/
	public final static short RT_RCDATA = 0x0a;
	/**Constant indicating message table resource type.*/
	public final static short RT_MESSAGETABLE = 0x0b;
	/**Constant indicating cursor group resource type.*/
	public final static short RT_GROUP_CURSOR = 0x0c;
	//0x0d is not defined...?
	/**Constant indicating icon group resource type.*/
	public final static short RT_GROUP_ICON = 0x0e;
	//0x0f is not defined...?
	/**Constant indicating version resource type.*/
	public final static byte RT_VERSION = 0x10;

	private short typeID;    //if >= 0x8000, then 
	private short count;     //number of resources of this type
	private int reserved;  //reserved...for what?
	private Resource[] resources;

	/**
	 * Constructs a new resource type.
	 * @param reader the binary reader
	 * @param rt the resource table
	 */
	ResourceType(FactoryBundledWithBinaryReader reader, ResourceTable rt) throws IOException {
		typeID = reader.readNextShort();
		if (typeID == 0) {
			return; //not a valid resource type...
		}

		count = reader.readNextShort();
		reserved = reader.readNextInt();

		ArrayList<Resource> list = new ArrayList<Resource>();

		int count_int = Conv.shortToInt(count);
		for (int i = 0; i < count_int; ++i) {
			if ((short) (typeID & 0x7fff) == RT_STRING) {
				list.add(new ResourceStringTable(reader, rt));
			}
			else {
				list.add(new Resource(reader, rt));
			}
		}
		resources = new Resource[list.size()];
		list.toArray(resources);
	}

	/**
	 * Returns the resource type ID.
	 * @return the resource type ID
	 */
	public short getTypeID() {
		return typeID;
	}

	/**
	 * Returns the number of resources of this type.
	 * @return the number of resources of this type
	 */
	public short getCount() {
		return count;
	}

	/**
	 * Returns the reserved value (purpose is unknown).
	 * @return the reserved value
	 */
	public int getReserved() {
		return reserved;
	}

	/**
	 * Returns the array of resources of this type.
	 * @return the array of resources of this type
	 */
	public Resource[] getResources() {
		return resources;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		if ((typeID & 0x8000) == 0) {
			return "UnknownResourceType_" + typeID;
		}
		int idx = typeID & 0x7fff;
		switch (idx) {
			case RT_CURSOR:
				return "Cursor";
			case RT_BITMAP:
				return "Bitmap";
			case RT_ICON:
				return "Icon";
			case RT_MENU:
				return "Menu";
			case RT_DIALOG:
				return "Dialog Box";
			case RT_STRING:
				return "String Table";
			case RT_FONTDIR:
				return "Font Directory";
			case RT_FONT:
				return "Font";
			case RT_ACCELERATOR:
				return "Accelerator Table";
			case RT_RCDATA:
				return "Resource Data";
			case RT_MESSAGETABLE:
				return "Message Table";
			case RT_GROUP_CURSOR:
				return "Cursor Directory";
			case RT_GROUP_ICON:
				return "Icon Directory";
			case RT_VERSION:
				return "Version Information";

			default:
				return "Unknown_" + idx;
		}
	}
}
