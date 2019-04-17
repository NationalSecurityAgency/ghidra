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
package ghidra.util.prop;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.LongIterator;
import ghidra.util.datastruct.NoSuchIndexException;

public class SaveableObjectPropertySetTest extends AbstractGenericTest {
	SaveableObjectPropertySet ps;

	@Before
	public void setUp() {
		ps = new SaveableObjectPropertySet("Test", SaveableInt.class);
	}

	@Test
	public void testGetSize() {
		for (int i = 0; i < 1000; i++) {
			ps.putObject(10000 * i, new SaveableInt(i));

		}
		assertEquals(1000, ps.getSize());
	}

	@Test
	public void testGetProperty() {
		for (int i = 0; i < 1000; i++) {
			ps.putObject(10000 * i, new SaveableInt(i));

		}

		assertEquals(new SaveableInt(0), ps.getObject(0));
		assertEquals(new SaveableInt(50), ps.getObject(500000));
		for (int i = 0; i < 1000; i++) {
			assertEquals(new SaveableInt(i), ps.getObject(10000 * i));
		}

		assertNull(ps.getObject(1));

	}

	@Test
	public void testPropertyIndex() throws NoSuchIndexException {
		for (int i = 0; i < 1000; i++) {
			ps.putObject(10000 * i, new SaveableInt(i));

		}

		assertEquals(0, ps.getFirstPropertyIndex());
		assertEquals(9990000, ps.getLastPropertyIndex());
		assertEquals(10000, ps.getNextPropertyIndex(0));
		assertEquals(0, ps.getPreviousPropertyIndex(10000));
		assertEquals(10000, ps.getNextPropertyIndex(1));
		assertEquals(0, ps.getPreviousPropertyIndex(2));

		LongIterator it = ps.getPropertyIterator();
		int count = 0;
		while (it.hasNext()) {
			it.next();
			count++;
		}
		assertEquals(1000, count);

	}

	@Test
	public void testPropertyIndex2() throws NoSuchIndexException {
		for (int i = 0; i < 10000; i++) {
			ps.putObject(3 * i, new SaveableInt(i));
		}
		assertEquals(10000, ps.getSize());

		assertEquals(0, ps.getFirstPropertyIndex());
		assertEquals(3 * 9999, ps.getLastPropertyIndex());
		assertEquals(3, ps.getNextPropertyIndex(0));
		assertEquals(0, ps.getPreviousPropertyIndex(3));
		assertEquals(3, ps.getNextPropertyIndex(1));
		assertEquals(0, ps.getPreviousPropertyIndex(2));

		LongIterator it = ps.getPropertyIterator();
		int count = 0;
		while (it.hasNext()) {
			it.next();
			count++;
		}
		assertEquals(10000, count);
	}

	@Test
	public void testPropertyIndex3() throws NoSuchIndexException {
		for (int i = 0; i < 10000; i++) {
			ps.putObject(i, new SaveableInt(i));
		}
		assertEquals(10000, ps.getSize());

		assertEquals(0, ps.getFirstPropertyIndex());
		assertEquals(9999, ps.getLastPropertyIndex());
		assertEquals(1, ps.getNextPropertyIndex(0));
		assertEquals(2, ps.getPreviousPropertyIndex(3));
		assertEquals(2, ps.getNextPropertyIndex(1));
		assertEquals(1, ps.getPreviousPropertyIndex(2));

		LongIterator it = ps.getPropertyIterator();
		int count = 0;
		while (it.hasNext()) {
			it.next();
			count++;
		}
		assertEquals(10000, count);
	}

	@Test
	public void testIterator() {
		for (int i = 0; i < 1000; i++) {
			ps.putObject(100 * i, new SaveableInt(i));
		}
		LongIterator it = ps.getPropertyIterator();
		int i = 0;
		while (it.hasNext()) {
			long l = it.next();
			assertEquals(100 * i, l);
			i++;
		}
		assertEquals(i, 1000);
	}

	@Test
	public void testIterator2() {
		for (int i = 0; i < 10000; i++) {
			ps.putObject(i, new SaveableInt(i));
		}
		LongIterator it = ps.getPropertyIterator();
		int i = 0;
		while (it.hasNext()) {
			long l = it.next();
			assertEquals(i, l);
			i++;
		}
		assertEquals(i, 10000);
	}

	@Test
	public void testSerialization() throws Exception {
		for (int i = 0; i < 10000; i++) {
			ps.putObject(i, new SaveableInt(i));
		}
		File tmpFile = createTempFile("SaveablePropertySetTest", ".ser");
		ObjectOutputStream out = null;
		ObjectInputStream in = null;
		try {
			out = new ObjectOutputStream(new FileOutputStream(tmpFile));
			out.writeObject(ps);
			out.close();

			ps = null;
			in = new ObjectInputStream(new BufferedInputStream(new FileInputStream(tmpFile)));
			ps = (SaveableObjectPropertySet) in.readObject();
			in.close();

			for (int i = 0; i < 10000; i++) {
				assertEquals(new SaveableInt(i), ps.getObject(i));
			}
		}
		finally {
			if (out != null) {
				try {
					out.close();
				}
				catch (IOException e) {
					// squash
				}
			}
			if (in != null) {
				try {
					in.close();
				}
				catch (IOException e) {
					// squash
				}
			}
			tmpFile.delete();
		}

	}//end doTest()

}
