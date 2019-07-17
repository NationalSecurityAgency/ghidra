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
package ghidra.program.model.address;

import ghidra.util.exception.UsrException;

/**
 * <p>An AddressOverflowException occurs when an attempt to
 * add or subtract a displacement would result in a value which
 * is outside the address space.
 */
public class AddressOverflowException extends UsrException {
    /**
     * <p>Constructs an AddressOverflowException with no detail message.<p>
     */
    public AddressOverflowException() {
        super("Displacement would result in an illegal address value.");
    }
    
    /**
     * <p>Constructs an AddressOverflowException with the specified
     * detail message.<p>
     *
     * @param message The message.
     */
    public AddressOverflowException(String message) {
        super(message);
    }
} 
