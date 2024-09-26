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
 * Converts byte values to Integer represented as an 4-byte/8-digit hex number.
 */
public class HexIntegerFormatModel extends HexValueFormatModel {

	public HexIntegerFormatModel() {
		super("Hex Integer", 4);
	}

	@Override
	public String getDataRepresentation(ByteBlock block, BigInteger index)
			throws ByteBlockAccessException {
		int i = block.getInt(index);
		String str = Integer.toHexString(i);
		return pad(str);
	}
}
