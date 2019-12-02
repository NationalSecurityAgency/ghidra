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
package ghidra.pcode.loadimage;

import ghidra.pcode.memstate.MemoryPage;
import ghidra.program.model.address.Address;

// API for accessing a binary load image
// using 1 of possibly many different methods behind the scenes
public interface LoadImage {

// TODO this doesn't appear to be used.
//    /**
//     * 
//     * @param ptr
//     * @param size
//     * @param addr
//     * @param bufOffset
//     * @param generateInitializedMask if true the function should return an initialized bit mask
//     * or null if all loaded bytes were known.  If true, uninitialized memory reads should only be 
//     * reflected in the mask and should not be reported via the memory fault handler.
//     * @return initialized bit mask or null (see generateInitializedMask parameter)
//     * @see MemoryPage
//     */
    public byte[] loadFill( byte[] buf, int size, Address addr, int bufOffset, boolean generateInitializedMask );

}
