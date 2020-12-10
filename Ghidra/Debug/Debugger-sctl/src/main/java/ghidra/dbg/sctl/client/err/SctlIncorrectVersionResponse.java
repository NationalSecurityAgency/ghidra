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

import ghidra.dbg.sctl.protocol.consts.Mkind;

/**
 * Thrown when the server selects an invalid version
 * 
 * The {@link Mkind#Rversion} reply must select a version from those listed in the
 * {@link Mkind#Tversion} request.
 */
public class SctlIncorrectVersionResponse extends SctlProtocolSequenceException {
	public SctlIncorrectVersionResponse(String message) {
		super(message);
	}
}
