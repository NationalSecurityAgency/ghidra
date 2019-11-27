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
package ghidra.javaclass.format;

import java.util.Arrays;

import ghidra.app.util.opinion.JavaLoader;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class JavaClassUtil {

	public final static long LOOKUP_ADDRESS = 0xE0000000L;
	//65536 is the maximum size of the methods_count item in a class file
	public static final long METHOD_INDEX_SIZE = 65536 * 4;

	public final static boolean isClassFile(Program program) {

		AddressFactory factory = program.getAddressFactory();
		byte[] bytes = new byte[4];
		try {
			AddressSpace space = factory.getAddressSpace(JavaLoader.CONSTANT_POOL);
			if (space != null) {
				Address address = space.getMinAddress();
				program.getMemory().getBytes(address, bytes);
			}
		}
		catch (Exception e) {
			Msg.error(JavaClassUtil.class, "Exception reading program bytes: " + e.getMessage(), e);
			return false;
		}
		return Arrays.equals(bytes, JavaClassConstants.MAGIC_BYTES);
	}

	public static Address toLookupAddress(Program program, int methodIndex) {
		AddressFactory addressFactory = program.getAddressFactory();
		AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();
		return defaultAddressSpace.getAddress(JavaClassUtil.LOOKUP_ADDRESS + (methodIndex * 4));
	}

}
