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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.util.HashMap;
import java.util.Map;

import ghidra.util.Msg;

/**
 * The PDB C13 Checksum Type
 */
public enum C13ChecksumType {
	UnknownChecksumType(-0x01),
	NoneChecksumType(0x00),
	Md5ChecksumType(0x01),
	Sha1ChecksumType(0x02),
	Sha256ChecksumType(0x03);

	private static final Map<Integer, C13ChecksumType> BY_VALUE = new HashMap<>();
	static {
		for (C13ChecksumType val : values()) {
			BY_VALUE.put(val.value, val);
		}
	}

	private final int value;

	public static C13ChecksumType fromValue(int val) {
		C13ChecksumType t = BY_VALUE.getOrDefault(val, UnknownChecksumType);
		if (t == UnknownChecksumType && val != UnknownChecksumType.value) {
			Msg.warn(null,
				String.format("PDB: C13FileChecksum - Unknown checksum type %08x", val));
		}
		return t;
	}

	private C13ChecksumType(int value) {
		this.value = value;
	}
}
