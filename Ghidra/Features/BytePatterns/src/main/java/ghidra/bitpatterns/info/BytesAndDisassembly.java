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
package ghidra.bitpatterns.info;

/**
 * This is a container class used by {@link ByteSequenceRowObject}.  It stores a {@link String} of
 * bytes and a {@link String} representing their disassembly
 */
public class BytesAndDisassembly {

	private String bytes;
	private String disassembly;

	public BytesAndDisassembly(String bytes, String disassembly) {
		this.bytes = bytes;
		this.disassembly = disassembly;
	}

	public String getBytes() {
		return bytes;
	}

	public String getDisassembly() {
		return disassembly;
	}

	@Override
	public int hashCode() {
		int hash = 17;
		hash = hash * 31 + bytes.hashCode();
		hash = hash * 31 + disassembly.hashCode();
		return hash;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof BytesAndDisassembly)) {
			return false;
		}
		BytesAndDisassembly bytesAndDis = (BytesAndDisassembly) o;
		return bytesAndDis.bytes.equals(bytes) && bytesAndDis.disassembly.equals(disassembly);
	}

}
