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
 * This is a ByteBlockInfo that also includes line index information. With the extra line index 
 * information, this object can be ordered and therefore, can implement {@link Comparable} 
 */
public class IndexedByteBlockInfo extends ByteBlockInfo
		implements Comparable<IndexedByteBlockInfo> {

	private BigInteger lineIndex;

	public IndexedByteBlockInfo(BigInteger lineIndex, ByteBlock block, BigInteger offset,
			int column) {
		super(block, offset, column);
		this.lineIndex = lineIndex;
	}

	@Override
	public int compareTo(IndexedByteBlockInfo o) {
		int result = lineIndex.compareTo(o.lineIndex);
		if (result == 0) {
			result = getOffset().compareTo(o.getOffset());
		}
		if (result == 0) {
			return Integer.compare(getColumn(), o.getColumn());
		}
		return result;
	}

}
