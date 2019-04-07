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
package ghidra.app.util.bin.format.ne;

import ghidra.app.util.bin.format.*;

import java.io.IOException;

/**
 * A class for storing new-executable resource names.
 * 
 * 
 */
public class ResourceName {
    private LengthStringSet lns;
    private long index;

	/**
	 * Constructs a resource name.
	 * @param reader the binary reader
	 */
    ResourceName(FactoryBundledWithBinaryReader reader) throws IOException {
        index = reader.getPointerIndex();

        lns = new LengthStringSet(reader);
    }

	/**
	 * Returns the length of the resource name.
	 * @return the length of the resource name
	 */
    public byte getLength() {
        return lns.getLength();
    }

	/**
	 * Returns the name of the resource name.
	 * @return the name of the resource name
	 */
    public String getName() {
        return lns.getString();
    }

	/**
	 * Returns the byte index of this resource name, relative to the beginning of the file.
	 * @return the byte index of this resource name
	 */
    public long getIndex() {
        return index;
    }
}
