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
package ghidra.program.model.data;

import java.util.Iterator;
import java.util.Map.Entry;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGTest;

public class NoisyStructureBuilderTest extends AbstractGTest {

	public void testNextField(Iterator<Entry<Long, DataType>> iter, long offset, DataType dt) {
		Assert.assertTrue(iter.hasNext());
		Entry<Long, DataType> entry = iter.next();
		Assert.assertEquals(offset, entry.getKey().longValue());
		Assert.assertTrue(entry.getValue() == dt);
	}

	@Test
	public void testBasicFields() {
		NoisyStructureBuilder builder = new NoisyStructureBuilder();
		builder.addDataType(12, Undefined4DataType.dataType);
		Pointer ptr = new Pointer32DataType(DWordDataType.dataType);
		builder.addReference(4, ptr);
		builder.addDataType(18, ShortDataType.dataType);
		builder.addReference(21, null);

		Iterator<Entry<Long, DataType>> iter = builder.iterator();
		testNextField(iter, 4, DWordDataType.dataType);
		testNextField(iter, 12, Undefined4DataType.dataType);
		testNextField(iter, 18, ShortDataType.dataType);
		Assert.assertFalse(iter.hasNext());
		Assert.assertEquals(builder.getSize(), 22);

		builder.addDataType(12, DWordDataType.dataType);
		builder.addDataType(4, Undefined4DataType.dataType);

		iter = builder.iterator();
		testNextField(iter, 4, DWordDataType.dataType);
		testNextField(iter, 12, DWordDataType.dataType);
		testNextField(iter, 18, ShortDataType.dataType);
		Assert.assertFalse(iter.hasNext());
		Assert.assertEquals(builder.getSize(), 22);
	}

	@Test
	public void testOverlaps() {
		NoisyStructureBuilder builder = new NoisyStructureBuilder();
		builder.addDataType(0, DWordDataType.dataType);
		builder.addDataType(4, ShortDataType.dataType);
		builder.addDataType(0, Undefined8DataType.dataType);
		Assert.assertEquals(builder.getSize(), 8);
		Iterator<Entry<Long, DataType>> iter = builder.iterator();
		testNextField(iter, 0, DWordDataType.dataType);
		testNextField(iter, 4, ShortDataType.dataType);
		Assert.assertFalse(iter.hasNext());
		Assert.assertEquals(builder.getSize(), 8);	// Undefined8 should expand size even though field isn't taken

		builder.addDataType(0, QWordDataType.dataType);		// Should replace everything
		iter = builder.iterator();
		testNextField(iter, 0, QWordDataType.dataType);
		Assert.assertFalse(iter.hasNext());
		Pointer ptr = new Pointer32DataType(DWordDataType.dataType);
		builder.addDataType(6, ptr);						// Partial overlap, should replace existing
		iter = builder.iterator();
		testNextField(iter, 6, ptr);
		Assert.assertFalse(iter.hasNext());
		Assert.assertEquals(builder.getSize(), 10);

		builder.addDataType(4, DWordDataType.dataType);		// Partial overlap, should replace
		iter = builder.iterator();
		testNextField(iter, 4, DWordDataType.dataType);
		Assert.assertFalse(iter.hasNext());

		builder = new NoisyStructureBuilder();
		builder.addDataType(4, Undefined8DataType.dataType);
		builder.addDataType(4, Undefined4DataType.dataType);
		builder.addDataType(8, DWordDataType.dataType);
		builder.addDataType(8, SignedDWordDataType.dataType);	// Less specific data-type
		iter = builder.iterator();
		testNextField(iter, 4, Undefined4DataType.dataType);
		testNextField(iter, 8, DWordDataType.dataType);
		Assert.assertFalse(iter.hasNext());
	}

	@Test
	public void testPointerNulls() {
		NoisyStructureBuilder builder = new NoisyStructureBuilder();
		DataType pointerNull = new Pointer32DataType(null);
		builder.addDataType(4, Undefined4DataType.dataType);
		builder.addDataType(8, Undefined4DataType.dataType);
		builder.addDataType(4, pointerNull);
		builder.addReference(16, pointerNull);

		Iterator<Entry<Long, DataType>> iter = builder.iterator();
		testNextField(iter, 4, pointerNull);
		testNextField(iter, 8, Undefined4DataType.dataType);
		Assert.assertFalse(iter.hasNext());
		Assert.assertEquals(builder.getSize(), 17);
	}
}
