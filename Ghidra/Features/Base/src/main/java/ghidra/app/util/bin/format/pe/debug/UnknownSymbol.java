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
package ghidra.app.util.bin.format.pe.debug;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Conv;
import ghidra.util.Msg;

class UnknownSymbol extends DebugSymbol{
    private byte [] unknown;

	UnknownSymbol(short length, short type, BinaryReader reader, int ptr) throws IOException {
		processDebugSymbol(length, type);
		try {
			unknown = reader.readByteArray(ptr, Conv.shortToInt(length));
		}
		catch (RuntimeException e) {
		    Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}

	}

	public byte[] getUnknown() {
		return unknown;
	}
}
