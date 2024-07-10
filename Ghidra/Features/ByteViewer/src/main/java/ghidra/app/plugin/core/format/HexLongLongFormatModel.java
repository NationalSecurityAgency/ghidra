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
package ghidra.app.plugin.core.format;

import java.math.BigInteger;

/**
 * Converts byte values to LongLong represented as an 16-byte/32-digit hex number.
 */
public class HexLongLongFormatModel extends HexValueFormatModel {

	public HexLongLongFormatModel() {
		super("Hex Long Long", 16);
	}

	@Override
	public String getDataRepresentation(ByteBlock block, BigInteger index)
			throws ByteBlockAccessException {
		long l0 = block.getLong(index);
		String str0 = pad(Long.toHexString(l0));
		long l1 = block.getLong(index.add(BigInteger.valueOf(8)));
		String str1 = pad(Long.toHexString(l1));
		String str = str1.substring(16) + str0.substring(16);
		return pad(str);
	}
}
