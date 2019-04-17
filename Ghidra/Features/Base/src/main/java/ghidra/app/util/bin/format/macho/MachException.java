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
package ghidra.app.util.bin.format.macho;

/**
 * An exception class to handle encountering
 * invalid Mach-O Headers.
 */
public class MachException extends Exception {

    /**
     * Constructs a new exception with the specified detail message.
     * @param   message   the detail message.
     */
	public MachException(String message) {
		super(message);
	}

    /**
     * Constructs a new exception with the specified cause and a detail message.
     * @param  cause the cause (which is saved for later retrieval by the method
     */
	public MachException(Exception cause) {
		super(cause);
	}

}
