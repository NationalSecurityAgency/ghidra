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
package ghidra.program.model.listing;

import ghidra.util.exception.UsrException;

/**
 * <CODE>DuplicateGroupException</CODE> is thrown when a fragment or child
 * is added to a module and that fragment or module is already a child.
 */
public class DuplicateGroupException extends UsrException {
    /**
     * Creates a new exception with the default message.
     */
    public DuplicateGroupException() {
        super("The fragment or module you are adding is already there.");
    }
    
    /**
     * Creates a new exception with the given user message.
     */
    public DuplicateGroupException(String usrMessage) {
        super(usrMessage);
    }
}
