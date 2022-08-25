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
package ghidra.pcode.emu;

/**
 * A simple p-code thread that operates on concrete bytes
 *
 * <p>
 * For a complete example of a p-code emulator, see {@link PcodeEmulator}. This is the default
 * thread for that emulator.
 */
public class BytesPcodeThread extends ModifiedPcodeThread<byte[]> {
	/**
	 * Construct a new thread
	 * 
	 * @see PcodeMachine#newThread(String)
	 * @param name the thread's name
	 * @param machine the machine to which the thread belongs
	 */
	public BytesPcodeThread(String name, AbstractPcodeMachine<byte[]> machine) {
		super(name, machine);
	}
}
