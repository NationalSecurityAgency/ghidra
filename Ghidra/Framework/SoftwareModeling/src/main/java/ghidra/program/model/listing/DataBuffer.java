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
package ghidra.program.model.listing;

import ghidra.program.model.address.Address;

/**
 * DataBuffer provides an array like interface into a set of Data
 * at a specific index.  Data can be retrieved by using a positive
 * offset from the current position.  The purpose of this class is to
 * provide an opaque storage mechanism for Data that is made up of other
 * Data items.
 *
 * This interface does not provide methods to reposition the data item
 * buffer.  This is so that it is clear that methods accepeting this
 * base class are not to mess which the base Address for this object.
 *
 */


public interface DataBuffer {

	/**
     * Get one Data item from the buffer at the current position plus offset.
     *
     * @param offset the displacement from the current position.
     *
     * @return the Data item at offset from the current position.
     *
	 * @throws ghidra.program.model.address.AddressOutOfBoundsException if offset exceeds
	 * address space
	 * @throws IndexOutOfBoundsException if offset is negative
     */
    public Data getData(int offset);

    /**
     * Get the next data item starting after offset.
     *
     * @param offset offset to look after
     *
     * @return Data item starting after this offset
     */
    public Data getDataAfter(int offset);

    /**
     * Get the previous data item starting before offset.
     *
     * @param offset offset to look before
     *
     * @return Data item starting before this offset
     */
    public Data getDataBefore(int offset);

    /**
     * Get the offset to the next data item found after offset.
     *
     * @param offset offset to look after
     *
     * @return offset of the first data item existing after this one.
     */
    public int getNextOffset(int offset);

    /**
     * Get the offset to the previous data item existing before this offset.
     *
     * @param offset offset to look before
     *
     * @return offset of the first data item existing before this one.
     */
    public int getPreviousOffset(int offset);

    /**
     * Get an array of data items that begin at or after start up to end.
     *   Data items that exist before start are not returned
     *   Data items that exist before end, but terminate after end ARE returned
     *   
     * @param start start offset
     * @param end end offset
     *
     * @return array of CodeDatas that exist between start and end.
     */
    public Data[] getData(int start, int end);

    /**
     * Get the Address which corresponds to the offset 0.
     *
     * @return the current address of offset 0.
     */
    public Address getAddress();
}
