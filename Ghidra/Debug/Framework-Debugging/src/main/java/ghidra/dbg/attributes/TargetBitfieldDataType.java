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
package ghidra.dbg.attributes;

/**
 * A bitfield-modified data type
 * 
 * This is only applicable to fields of structures.
 */
public interface TargetBitfieldDataType extends TargetDataType {
	public class DefaultTargetBitfieldDataType implements TargetBitfieldDataType {
		protected final TargetDataType fieldType;
		protected final int leastBitPosition;
		protected final int bitLength;

		public DefaultTargetBitfieldDataType(TargetDataType fieldType, int leastBitPosition,
				int bitLength) {
			this.fieldType = fieldType;
			this.leastBitPosition = leastBitPosition;
			this.bitLength = bitLength;
		}

		@Override
		public TargetDataType getFieldType() {
			return fieldType;
		}

		@Override
		public int getLeastBitPosition() {
			return leastBitPosition;
		}

		@Override
		public int getBitLength() {
			return bitLength;
		}
	}

	TargetDataType getFieldType();

	int getLeastBitPosition();

	int getBitLength();
}
