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
package db;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Arrays;

import org.junit.*;

import generic.test.AbstractGenericTest;

public class DBBufferTest extends AbstractGenericTest {

	private static final int BUFFER_SIZE = 256;
	private static final int CACHE_SIZE = 4 * 1024 * 1024;

	private DBHandle dbh;

	@Before
	public void setup() throws IOException {
		dbh = new DBHandle(BUFFER_SIZE, CACHE_SIZE);
	}

	@After
	public void tearDown() {
		if (dbh != null) {
			dbh.close();
		}
	}

	@Test
	public void testCreatePutAndGet() throws IOException {
		DBBuffer buf = null;
		try {
			buf = dbh.createBuffer(1000);
			fail("Expected check transaction failure");
		}
		catch (NoTransactionException e) {
			// expected
		}

		long txId = dbh.startTransaction();
		try {
			buf = dbh.createBuffer(1000);
		}
		catch (NoTransactionException e) {
			fail("Unexpected check transaction failure");
		}
		finally {
			dbh.endTransaction(txId, true);
		}

		int bufId = buf.getId();

		byte[] bytes = new byte[] { 1, 2, 3, 4, 5 };
		byte[] data = new byte[bytes.length];

		buf.get(0, data);
		assertTrue("Expected all zero bytes in buffer",
			Arrays.equals(new byte[bytes.length], data));

		try {
			buf.put(0, bytes);
			fail("Expected check transaction failure");
		}
		catch (NoTransactionException e) {
			// expected
		}

		txId = dbh.startTransaction();
		try {
			buf.put(0, bytes);
		}
		catch (NoTransactionException e) {
			fail("Unexpected check transaction failure");
		}
		finally {
			dbh.endTransaction(txId, true);
		}

		buf.get(0, data);
		assertTrue("Expected bytes in buffer", Arrays.equals(bytes, data));

		dbh.undo();
		buf = dbh.getBuffer(bufId); // must re-acquire after undo

		buf.get(0, data);
		assertTrue("Expected all zero bytes in buffer",
			Arrays.equals(new byte[bytes.length], data));

		dbh.redo();
		buf = dbh.getBuffer(bufId); // must re-acquire after redo

		buf.get(0, data);
		assertTrue("Expected bytes in buffer", Arrays.equals(bytes, data));

	}

	@Test
	public void testDelete() throws IOException {

		DBBuffer buf = null;

		long txId = dbh.startTransaction();
		try {
			buf = dbh.createBuffer(1000);
		}
		catch (NoTransactionException e) {
			fail("Unexpected check transaction failure");
		}
		finally {
			dbh.endTransaction(txId, true);
		}

		int bufId = buf.getId();

		try {
			buf.delete();
			fail("Expected check transaction failure");
		}
		catch (NoTransactionException e) {
			// expected
		}

		txId = dbh.startTransaction();
		try {
			buf.delete();
		}
		catch (NoTransactionException e) {
			fail("Unexpected check transaction failure");
		}
		finally {
			dbh.endTransaction(txId, true);
		}

		try {
			buf = dbh.getBuffer(bufId); // must re-acquire after redo
			fail("Expected invalid buffer error");
		}
		catch (IOException e) {
			// expected
		}

		dbh.undo();
		buf = dbh.getBuffer(bufId);
		assertEquals("Expected valid buffer", 0, buf.getByte(0));

	}
}
