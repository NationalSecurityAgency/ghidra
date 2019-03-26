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
package ghidra.app.util.bin.format.lx;

import ghidra.app.util.bin.ByteProvider;
import ghidra.util.exception.NotYetImplementedException;

/**
 * A class to manage loading Linear Executables (LX).
 * 
 * NOTE: this is not implemented yet.
 */
public class LinearExecutable {
	/**
	 * The magic number for LX executables.
	 */
    public final static short IMAGE_LX_SIGNATURE = 0x584c; //LX

    public LinearExecutable(ByteProvider bp) {
        throw new NotYetImplementedException();
    }
}
