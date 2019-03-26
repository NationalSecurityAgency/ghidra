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
package ghidra.util.exception;

/**
 * Base Class for all ghidra non-runtime exceptions
 */
public class UsrException extends Exception {

    
    /**
     * Construct a new UsrException with no message
     */
    public UsrException() {
        super();
    }
    
    /**
     * Construct a new UsrException with the given message
     * 
     * @param msg    the exception message
     */
    public UsrException(String msg) {
        super(msg);
    }
    
    /**
     * Construct a new UsrException with the given message and cause
     * 
     * @param msg    the exception message
     * @param cause  the exception cause
     */
    public UsrException(String msg, Throwable cause) {
    	super(msg, cause);
    }
}
