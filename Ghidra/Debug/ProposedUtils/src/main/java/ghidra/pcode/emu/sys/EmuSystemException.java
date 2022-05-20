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

import ghidra.pcode.exec.PcodeExecutionException;
import ghidra.pcode.exec.PcodeFrame;

/**
 * A p-code execution exception related to system simulation
 */
public class EmuSystemException extends PcodeExecutionException {
	public EmuSystemException(String message) {
		super(message);
	}

	public EmuSystemException(String message, PcodeFrame frame) {
		super(message, frame);
	}

	public EmuSystemException(String message, PcodeFrame frame, Throwable cause) {
		super(message, frame, cause);
	}
}
