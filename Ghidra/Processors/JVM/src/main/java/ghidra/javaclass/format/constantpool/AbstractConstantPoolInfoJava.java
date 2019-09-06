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
package ghidra.javaclass.format.constantpool;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * Java virtual machine instructions do not rely on the runtime layout of classes,
 * interfaces, class instances, or arrays. Instead, instructions refer to symbolic
 * information in the constant_pool table.
 * <p>
 * All constant_pool table entries have the following general format:
 * <pre>
 * 		cp_info {
 * 			u1 tag;
 * 			u1 info[];
 * 		}
 * </pre>
 * Each item in the constant_pool table must begin with a 1-byte tag indicating
 * the kind of cp_info entry. The contents of the info array vary with the value of
 * tag. The valid tags and their values are listed in Table 4.3. Each tag byte must be
 * followed by two or more bytes giving information about the specific constant. The
 * format of the additional information varies with the tag value.
 *
 */
public abstract class AbstractConstantPoolInfoJava implements StructConverter {

	private long _offset;
	private byte tag;

	protected AbstractConstantPoolInfoJava(BinaryReader reader) throws IOException {
		_offset = reader.getPointerIndex();

		tag = reader.readNextByte();
	}

	public long getOffset() {
		return _offset;
	}

	public byte getTag() {
		return tag;
	}

}
