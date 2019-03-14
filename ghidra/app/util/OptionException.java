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
package ghidra.app.util;

/**
 * Exception thrown if there was a problem accessing an Option, or if
 * an informational message is to be conveyed.
 * 
 * 
 */
public class OptionException extends Exception {

    private boolean isInfo;
    
	/**
	 * Construct a new OptionException.
	 * @param msg reason for the exception
	 */
	public OptionException(String msg) {
		super(msg);
	}
	
	/**
	 * Construct a new OptionException that may be an informational message
	 * if isValid is true.
	 * @param msg message to display
	 * @param isInfo true if the msg is in informational message
	 */
	public OptionException(String msg, boolean isInfo) {
	    super(msg);
	    this.isInfo = isInfo;
	}
	
	/**
	 * Return whether the message associated with this exception is
	 * informational.
	 */
	public boolean isInfoMessage() {
	    return isInfo;
	}

}
