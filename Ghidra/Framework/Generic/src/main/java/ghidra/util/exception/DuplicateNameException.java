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
 * Exception thrown whenever a method tries give something a name and that name is already used.
 */
public class DuplicateNameException extends UsrException {
	
    /**
     * constructs a new DuplicatenameException with a default message.
     */
    public DuplicateNameException() {
		super("That name is already in use.");
	}

    /**
     * construct a new DuplicateNameException with a given message.
     *
     * @param usrMessage overides the default message.
     */
	public DuplicateNameException(String usrMessage) {
		super(usrMessage);
	}
}
