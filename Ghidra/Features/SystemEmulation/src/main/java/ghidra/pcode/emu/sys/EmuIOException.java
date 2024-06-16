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
package ghidra.pcode.emu.sys;

import java.io.IOException;

/**
 * The simulated system interrupted with an I/O error
 * 
 * <p>
 * This exception is for I/O errors within the simulated system. If the host implementation causes a
 * real {@link IOException}, it should <em>not</em> be wrapped in this exception unless, e.g., a
 * simulated file system intends to proxy the real file system.
 */
public class EmuIOException extends EmuInvalidSystemCallException {

	public EmuIOException(String message, Throwable cause) {
		super(message, cause);
	}

	public EmuIOException(String message) {
		super(message);
	}
}
