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
 * <p>NotYetImplementedException is used during development of a class.
 * It is expected that this Exception should not exist in final
 * released classes.</p>
 *
 * @version 1999/02/05
 */

public class NotYetImplementedException extends RuntimeException {
	
	/**
	 * <p>Constructs a NotYetImplementedException with no detail message.<p>
	 */
	public NotYetImplementedException() {
		super();
    }
	
	/**
	 * <p>Constructs a NotYetImplementedException with the specified
	 * detail message.<p>
	 *
	 * @param message The message.
	 */
	public NotYetImplementedException(String message) {
		super(message);
	}
	
} // NotYetImplementedException
