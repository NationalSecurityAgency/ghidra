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
package ghidra.app.util.bin.format.pef;

/**
 * Packed Data Contents
 * 
 * See Apple's -- IOPEFInternals.h
 */
public enum PackedDataOpcodes {

	/** Zero fill "count" bytes.*/
	kPEFPkDataZero(0),
	/** Block copy "count" bytes.*/
	kPEFPkDataBlock(1),
	/** Repeat "count" bytes "count2"+1 times.*/
	kPEFPkDataRepeat(2),
	/** Interleaved repeated and unique data.*/
	kPEFPkDataRepeatBlock(3),
	/** Interleaved zero and unique data.*/
	kPEFPkDataRepeatZero(4),
	/** Reserved. */
	kPEFPkDataReserved5(5),
	/** Reserved. */
	kPEFPkDataReserved6(6),
	/** Reserved. */
	kPEFPkDataReserved7(7);

	private int	value;

	private PackedDataOpcodes(int value) {
		this.value = value;
	}

	public int getValue() {
		return value;
	}

	public static PackedDataOpcodes get(int value) {
		PackedDataOpcodes [] opcodes = values();
		for (PackedDataOpcodes opcode : opcodes) {
			if (opcode.value == value) {
				return opcode;
			}
		}
		throw new IllegalArgumentException();
	}
}
