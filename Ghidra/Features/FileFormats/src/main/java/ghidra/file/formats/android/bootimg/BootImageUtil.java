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
package ghidra.file.formats.android.bootimg;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.Arrays;

public class BootImageUtil {
	
	public final static boolean isBootImage( Program program ) {
		byte [] bytes = new byte[ 8 ];
		try {
			Address address = program.getMinAddress();
			program.getMemory().getBytes( address, bytes );
		}
		catch (Exception e) {}
		return Arrays.equals( bytes, BootImageConstants.BOOT_IMAGE_MAGIC_BYTES );
	}

}
