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
package ghidra.util.datastruct;


import ghidra.util.exception.UsrException;
/**
 * Exception thrown if a requested index does not exist.
 */
public class NoSuchIndexException extends UsrException {
	
	/** Static constructor for this exception with a generic message. 
	 * Use this for efficiency when the actual stack information isn't needed. 
	 */
    public static final NoSuchIndexException noSuchIndexException = new NoSuchIndexException();

    /**
     * Default constructor
     */
    public NoSuchIndexException() {
        super("Index does not exist.");
    }

    /**
     * Constructor
     * @param msg detailed message
     */
    public NoSuchIndexException(String msg) {
        super(msg);
    }
}
