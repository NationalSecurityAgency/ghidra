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

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.util.Conv;

/**
 * An implementation of the new-executable TNAMEINFO structure.
 * 
 * 
 */
public class Resource {
	/**The resources is not fixed.*/
	public final static short FLAG_MOVEABLE = 0x0010;
	/**The resource can be shared.*/
	public final static short FLAG_PURE = 0x0020;
	/**The resource is preloaded.*/
	public final static short FLAG_PRELOAD = 0x0040;

	private FactoryBundledWithBinaryReader reader;
	private ResourceTable rt;
	private short fileOffset; //this value must be shifted
	private short fileLength; //this value must be shifted
	private short flagword;
	private short resourceID;
	private short handle; //reserved
	private short usage; //reserved

	Resource(FactoryBundledWithBinaryReader reader, ResourceTable rt) throws IOException {
		this.reader = reader;
		this.rt = rt;
		fileOffset = reader.readNextShort();
		fileLength = reader.readNextShort();
		flagword = reader.readNextShort();
		resourceID = reader.readNextShort();
		handle = reader.readNextShort();
		usage = reader.readNextShort();
	}

	/**
	 * Returns the file offset of this resource.
	 * @return the file offset of this resource
	 */
	public short getFileOffset() {
		return fileOffset;
	}

	/**
	 * Returns the file length of this resource.
	 * @return the file length of this resource
	 */
	public short getFileLength() {
		return fileLength;
	}

	/**
	 * Returns the flag word of this resource.
	 * @return the flag word of this resource
	 */
	public short getFlagword() {
		return flagword;
	}

	/**
	 * Returns the resource ID of this resource.
	 * @return the resource ID of this resource
	 */
	public short getResourceID() {
		return resourceID;
	}

	/**
	 * Returns the handle of this resource.
	 * @return the handle of this resource
	 */
	public short getHandle() {
		return handle;
	}

	/**
	 * Returns the usage of this resource.
	 * @return the usage of this resource
	 */
	public short getUsage() {
		return usage;
	}

	/**
	 * Returns true if this resource is moveable.
	 * @return true if this resource is moveable
	 */
	public boolean isMoveable() {
		return (flagword & FLAG_MOVEABLE) != 0;
	}

	/**
	 * Returns true if this resource is pure.
	 * @return true if this resource is pure
	 */
	public boolean isPure() {
		return (flagword & FLAG_PURE) != 0;
	}

	/**
	 * Returns true if this resource is preloaded.
	 * @return true if this resource is preloaded
	 */
	public boolean isPreload() {
		return (flagword & FLAG_PRELOAD) != 0;
	}

	/**
	 * Returns the shifted file offset of this resource.
	 * <code>this.getFileOffset() &lt;&lt; ResourceTable.getAlignmentShiftCount()</code>
	 * @return the shifted file offset of this resource
	 */
	public int getFileOffsetShifted() {
		int shift_int = Conv.shortToInt(rt.getAlignmentShiftCount());
		int offset_int = Conv.shortToInt(fileOffset);
		return offset_int << shift_int;
	}

	/**
	 * Returns the shifted file length of this resource.
	 * <code>this.getFileLength() &lt;&lt; ResourceTable.getAlignmentShiftCount()</code>
	 * @return the shifted file length of this resource
	 */
	public int getFileLengthShifted() {
		int shift_int = Conv.shortToInt(rt.getAlignmentShiftCount());
		int length_int = Conv.shortToInt(fileLength);
		return length_int << shift_int;
	}

	/**
	 * Returns the actual bytes for this resource.
	 * @return the actual bytes for this resource
	 */
	public byte[] getBytes() throws IOException {
		return reader.readByteArray(getFileOffsetShifted(), getFileLengthShifted());
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		//if MSB is set, then resourceID is a unique id of this resource...
		if ((resourceID & 0x8000) != 0) {
			return "" + (resourceID & 0x7fff);
		}
		//if the MSB is not set, then resourceID is an 
		//index to a resource name relative to the 
		//beginning of the resource table...
		ResourceName[] names = rt.getResourceNames();
		for (ResourceName name : names) {
			if (resourceID == name.getIndex() - rt.getIndex()) {
				return name.getName();
			}
		}
		if (resourceID >= 0 && resourceID < names.length) {
			return names[resourceID].getName();
		}
		return ("NE - Resource - unknown id - " + Conv.toHexString(resourceID));
	}
}
