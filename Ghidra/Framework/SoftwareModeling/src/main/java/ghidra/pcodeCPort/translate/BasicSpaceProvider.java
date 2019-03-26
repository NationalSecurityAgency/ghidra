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
package ghidra.pcodeCPort.translate;

import ghidra.pcodeCPort.space.AddrSpace;

public interface BasicSpaceProvider {

    /// Most processors have a main address bus, on which the bulk
    /// of the processor's RAM is mapped.  Everything referenced
    /// with this address bus should be modeled in pcode with a
    /// single address space, referred to as the \e default space.
    /// \return a pointer to the \e default space
    public AddrSpace getDefaultSpace();

    /// Pcode represents constant values within an operation as
    /// offsets within a special \e constant address space. 
    /// (See ConstantSpace)
    /// \return a pointer to the \b constant space
    public AddrSpace getConstantSpace();

}
