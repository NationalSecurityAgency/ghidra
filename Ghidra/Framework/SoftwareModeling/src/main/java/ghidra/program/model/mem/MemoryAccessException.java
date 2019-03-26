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
package ghidra.program.model.mem;

import ghidra.util.exception.UsrException;
/**
 * <p>An MemoryAccessException indicates that the attempted
 * memory access is not permitted.  (i.e. Readable/Writeable)</p>
 *
 * @version 1999-03-31
 */
public class MemoryAccessException extends UsrException
{
    /**
     * <p>Constructs an MemoryAccessException with no detail message.<p>
     */
    public MemoryAccessException() {
        super();
    }
    
    
    /**
     * <p>Constructs an MemoryAccessException with the specified
     * detail message.<p>
     *
     * @param message The message.
     */
    public MemoryAccessException(String message) {
        super(message);
    }
} // MemoryAccessException
