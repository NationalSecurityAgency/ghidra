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
package ghidra.program.model.scalar;
 
/**
 * <p>A ScalarOverflowException indicates that some precision would
 * be lost.  If the operation was signed, unused bits did not match the
 * sign bit.  If the operation was unsigned, unsed bits were not all
 * zero</p>
 *
 * @version 1999-03-31
 */
public class ScalarOverflowException extends RuntimeException {
    
    /**
     * <p>Constructs a ScalarOverflowException with no detail message.<p>
     */
    public ScalarOverflowException() {
        super("Scalar overflow");
    }
    
    /**
     * <p>Constructs a ScalarOverflowException with the specified
     * detail message.<p>
     *
     * @param message The message.
     */
    public ScalarOverflowException(String message) {
        super(message);
    }
} // ScalarOverflowException
