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
 * <CODE>SegmentMismatchException</CODE> is thrown when two
 * addresses with different segments are used in an operation
 * that requires the same segment.
 */
public class SegmentMismatchException extends UsrException {
    /**
     * <p>Constructs a SegmentMismatchException with no detail message.<p>
     */
    public SegmentMismatchException() {
        super("The segments of the addresses do not match.");
    }
    
    /**
     * <p>Constructs a SegmentMismatchException with the specified
     * detail message.<p>
     *
     * @param message The message.
     */
    public SegmentMismatchException(String message) {
        super(message);
    }
} 
