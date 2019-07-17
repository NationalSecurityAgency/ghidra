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
package ghidra.feature.fid.hash;

/**
 * Implementation container class for FidHashQuad. 
 */
class FidHashQuadImpl implements FidHashQuad {
	final short codeUnitSize;
	final long fullHash;
	final byte specificHashAdditionalSize;
	final long specificHash;

	/**
	 * Constructs a FidHashQuadImpl with the given values. 
	 * @param codeUnitSize the full hash size
	 * @param fullHash the full hash
	 * @param specificHashAdditionalSize the specific hash additional hash size
	 * @param specificHash the specific hash
	 */
	FidHashQuadImpl(short codeUnitSize,long fullHash, byte specificHashAdditionalSize, long specificHash) {
		this.codeUnitSize = codeUnitSize;
		this.fullHash = fullHash;
		this.specificHashAdditionalSize = specificHashAdditionalSize;
		this.specificHash = specificHash;
	}

	@Override
	public short getCodeUnitSize() {
		return codeUnitSize;
	}

	@Override
	public long getFullHash() {
		return fullHash;
	}

	@Override
	public byte getSpecificHashAdditionalSize() {
		return specificHashAdditionalSize;
	}

	@Override
	public long getSpecificHash() {
		return specificHash;
	}

	/**
	 * Overridden toString for useful debug printing.
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		sb.append(" FH: ");
		sb.append(Long.toHexString(fullHash));
		sb.append(" (");
		sb.append(Short.toString(codeUnitSize));

		sb.append(") +");
		sb.append(specificHashAdditionalSize);
		sb.append(" XH: ");
		sb.append(Long.toHexString(specificHash));

		return sb.toString();
	}
}
