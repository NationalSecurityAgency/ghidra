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
package ghidra.file.formats.ios.img3.tag;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.ios.img3.AbstractImg3Tag;

import java.io.IOException;

public class TypeTag extends AbstractImg3Tag {
	private int type;
	private int unknown0;
	private int unknown1;
	private int unknown2;
	private int unknown3;

	TypeTag(BinaryReader reader) throws IOException {
		super(reader);

		type      =  reader.readNextInt();
		unknown0  =  reader.readNextInt();
		unknown1  =  reader.readNextInt();
		unknown2  =  reader.readNextInt();
		unknown3  =  reader.readNextInt();
	}

	public int getType() {
		return type;
	}
	public int getUnknown0() {
		return unknown0;
	}
	public int getUnknown1() {
		return unknown1;
	}
	public int getUnknown2() {
		return unknown2;
	}
	public int getUnknown3() {
		return unknown3;
	}
}
