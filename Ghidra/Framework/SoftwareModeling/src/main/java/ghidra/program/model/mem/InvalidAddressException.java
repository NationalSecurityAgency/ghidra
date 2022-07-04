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
package ghidra.program.model.mem;

import ghidra.util.exception.UsrException;

/**
 * Exception for invalid address either due to improper format
 * or address not defined within target
 */
public class InvalidAddressException extends UsrException {
    
	/**
	 * Constructs a new InvalidAddressException
	 */
    public InvalidAddressException() {
		super();
    }
	
	/**
	 * Constructs a new InvalidAddressException with a detailed message.
	 * 
	 * @param msg detailed message
	 */
    public InvalidAddressException(String msg) {
        super(msg);
    }
}
 
