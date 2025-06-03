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

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.Msg;

class S_END extends DebugSymbol {

	S_END(short length, short type, BinaryReader reader, int ptr) {
		processDebugSymbol(length, type);
		Msg.debug(this, reader.getPointerIndex() + " -- " + ptr);
		this.name = "END";
		this.offset = 0;
		this.section = 0;
    }

}
