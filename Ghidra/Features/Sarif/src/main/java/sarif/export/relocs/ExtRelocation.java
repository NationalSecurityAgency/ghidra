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
package sarif.export.relocs;

import org.apache.commons.lang3.StringUtils;

import ghidra.program.model.data.ISF.IsfObject;
import ghidra.program.model.reloc.Relocation;

public class ExtRelocation implements IsfObject {

	String name;
	String kind;
	String value;
	String bytes;

	public ExtRelocation(Relocation reloc) {
		kind = Integer.toString(reloc.getType());
		value = pack(reloc.getValues());
		String packedBytes = pack(reloc.getBytes());
		if (packedBytes != null) {
			bytes = packedBytes;
		}
		String symName = reloc.getSymbolName();
		if (!StringUtils.isEmpty(symName)) {
			name = reloc.getSymbolName();
		}
	}

	private String pack(long[] values) {
		if (values == null || values.length == 0) {
			return "";
		}
		StringBuffer buf = new StringBuffer();
		for (long v : values) {
			if (buf.length() != 0) {
				buf.append(',');
			}
			buf.append("0x" + Long.toHexString(v));
		}
		return buf.toString();
	}
	
	private String pack(byte[] values) {
		if (values == null || values.length == 0) {
			return null;
		}
		StringBuffer buf = new StringBuffer();
		for (byte v : values) {
			if (buf.length() != 0) {
				buf.append(',');
			}
			buf.append("0x" + Integer.toHexString(v & 0xff));
		}
		return buf.toString();
	}

}
