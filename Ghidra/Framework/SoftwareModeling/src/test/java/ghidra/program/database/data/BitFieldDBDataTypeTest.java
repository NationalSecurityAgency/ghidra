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
package ghidra.program.database.data;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.model.data.*;

public class BitFieldDBDataTypeTest extends AbstractGTest {

	private DataTypeManagerDB dataMgr;

	@Before
	public void setup() throws Exception {
		dataMgr = new StandAloneDataTypeManager("dummyDTM");
		dataMgr.startTransaction("Test");
	}

	@Test
	public void testGetIdAndGetDataTypeFromId() throws Exception {

		testRoundTrip(new BitFieldDBDataType(CharDataType.dataType, 1, 4));
		testRoundTrip(new BitFieldDBDataType(CharDataType.dataType, 2, 6));
		testRoundTrip(new BitFieldDBDataType(ShortDataType.dataType, 3, 2));
		testRoundTrip(new BitFieldDBDataType(UnsignedShortDataType.dataType, 4, 4));
		testRoundTrip(new BitFieldDBDataType(IntegerDataType.dataType, 5, 7));
		testRoundTrip(new BitFieldDBDataType(UnsignedIntegerDataType.dataType, 14, 2));
		testRoundTrip(new BitFieldDBDataType(LongDataType.dataType, 27, 2));
		testRoundTrip(new BitFieldDBDataType(UnsignedLongDataType.dataType, 6, 0));
		testRoundTrip(new BitFieldDBDataType(LongLongDataType.dataType, 6, 2));
		testRoundTrip(new BitFieldDBDataType(UnsignedLongLongDataType.dataType, 6, 2));

		// non-standard integer base types
		testRoundTrip(new BitFieldDBDataType(ByteDataType.dataType, 6, 2));
		testRoundTrip(new BitFieldDBDataType(QWordDataType.dataType, 6, 2));

		// TypeDef base types
		TypeDef foo = new TypedefDataType("foo", IntegerDataType.dataType);
		testRoundTrip(new BitFieldDBDataType(foo, 6, 3));

		// Enum base types
		EnumDataType fum = new EnumDataType("fum", 4);
		fum.add("A", 1);
		testRoundTrip(new BitFieldDBDataType(fum, 6, 2));

	}

	private void testRoundTrip(BitFieldDataType packedBitFieldDataType) throws Exception {

		// must resolve first to ensure that TypeDef ID can be encoded within ID,
		// otherwise it will be omitted from ID if TypeDef does not already exist
		// within corresponding data type manager.

		// This is intended to replicate the order of events when a bit-field
		// component is established where the component size corresponds to the 
		// exact storage size determined by the BitFieldAccumulator during packing

		BitFieldDataType bitFieldDataType =
			(BitFieldDataType) dataMgr.resolve(packedBitFieldDataType, null);

		long id = BitFieldDBDataType.getId(bitFieldDataType);

		// The only thing which is preserved is the bitSize, storageSize and bitOffset/Shift

		bitFieldDataType = BitFieldDBDataType.getBitFieldDataType(id, dataMgr);

		assertEquals(packedBitFieldDataType.getBitSize(), bitFieldDataType.getBitSize());
		assertEquals(packedBitFieldDataType.getDeclaredBitSize(),
			bitFieldDataType.getDeclaredBitSize());
		assertEquals(packedBitFieldDataType.getBitOffset(), bitFieldDataType.getBitOffset());
		assertEquals(packedBitFieldDataType.getStorageSize(), bitFieldDataType.getStorageSize());
	}

}
