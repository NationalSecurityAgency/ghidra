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
package ghidra.file.formats.ios.apple8900;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.Arrays;

public final class Apple8900Util {

	public final static boolean is8900(Program program) {
		Address address = program.getMinAddress();
		byte [] bytes = new byte[4];
		try {
			program.getMemory().getBytes(address, bytes);
		}
		catch (Exception e) {}
		return Arrays.equals(bytes, Apple8900Constants.MAGIC_BYTES);
	}
}
