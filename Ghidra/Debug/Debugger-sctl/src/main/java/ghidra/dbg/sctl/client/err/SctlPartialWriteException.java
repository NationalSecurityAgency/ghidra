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
package ghidra.dbg.sctl.client.err;

import ghidra.dbg.sctl.err.SctlRuntimeException;
import ghidra.util.NumericUtilities;

/**
 * Thrown when fewer bytes than those given are written by the server
 * 
 * The {@code Rwrite} reply contains a field for the server to report how many bytes of data from a
 * {@code Twrite} request were actually written. Ideally, all bytes are written, so this is thrown
 * if fewer are reported.
 */
public class SctlPartialWriteException extends SctlRuntimeException {
	public SctlPartialWriteException(byte[] data, int len) {
		super("Only wrote " + len + " bytes  of " + NumericUtilities.convertBytesToString(data));
	}
}
