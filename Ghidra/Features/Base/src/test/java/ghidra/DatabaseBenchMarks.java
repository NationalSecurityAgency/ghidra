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
package ghidra;

import java.io.IOException;
import java.util.Random;

import db.*;

public class DatabaseBenchMarks {
	static int BUFFER_SIZE = 16 * 1024;
	static int CACHE_SIZE = 32 * 1024 * 1024;

	public static void main(String[] args) {
		TestTimer timer = new TestTimer();

		testOrderedIntInsertions(timer, 1000);
		testOrderedIntInsertions(timer, 10000);
		testOrderedIntInsertions(timer, 100000);
		testOrderedIntInsertions(timer, 1000000);

		System.out.println("");
		testOrderedStringInsertions(timer, 1000);
		testOrderedStringInsertions(timer, 10000);
		testOrderedStringInsertions(timer, 100000);
		testOrderedStringInsertions(timer, 1000000);

		System.out.println("");
		testRandomIntInsertions(timer, 1000);
		testRandomIntInsertions(timer, 10000);
		testRandomIntInsertions(timer, 100000);
		testRandomIntInsertions(timer, 1000000);

		System.out.println("");
		testIteration(timer);

		System.out.println("");
		testRandomAccess(timer);

	}

	private static void testOrderedIntInsertions(TestTimer timer, int numInsertions) {
		try {
			DBHandle dbh = new DBHandle(BUFFER_SIZE, CACHE_SIZE);
			long transactionID = dbh.startTransaction();
			Schema schema =
				new Schema(1, "Key", new Field[] { IntField.INSTANCE }, new String[] { "Value" });
			Table table = dbh.createTable("Test", schema);
			DBRecord record = schema.createRecord(0);
			timer.start(
				"Inserting " + numInsertions + " sorted records with long keys and integer values");
			for (int i = 0; i < numInsertions; i++) {
				record.setKey(i);
				record.setIntValue(0, i);
				table.putRecord(record);
			}
			timer.end();
			dbh.endTransaction(transactionID, true);
			dbh.close();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void testOrderedStringInsertions(TestTimer timer, int numInsertions) {
		try {
			DBHandle dbh = new DBHandle(BUFFER_SIZE, CACHE_SIZE);
			long transactionID = dbh.startTransaction();
			Schema schema = new Schema(1, "Key", new Field[] { StringField.INSTANCE },
				new String[] { "Value" });
			Table table = dbh.createTable("Test", schema);
			DBRecord record = schema.createRecord(0);
			timer.start("Inserting " + numInsertions +
				" sorted records with long keys and String (length = 8) values");
			for (int i = 0; i < numInsertions; i++) {
				record.setKey(i);
				record.setString(0, "abcdefgh");
				table.putRecord(record);
			}
			timer.end();
			dbh.endTransaction(transactionID, true);
			dbh.close();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void testRandomIntInsertions(TestTimer timer, int numInsertions) {
		try {
			Random random = new Random();
			DBHandle dbh = new DBHandle(BUFFER_SIZE, CACHE_SIZE);
			long transactionID = dbh.startTransaction();
			Schema schema =
				new Schema(1, "Key", new Field[] { IntField.INSTANCE }, new String[] { "Value" });
			Table table = dbh.createTable("Test", schema);
			DBRecord record = schema.createRecord(0);
			timer.start(
				"Inserting " + numInsertions + " random records with long keys and integer values");
			for (int i = 0; i < numInsertions; i++) {
				record.setKey(random.nextLong());
				record.setIntValue(0, i);
				table.putRecord(record);
			}
			timer.end();
			dbh.endTransaction(transactionID, true);
			dbh.close();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void testIteration(TestTimer timer) {
		try {
			DBHandle dbh = new DBHandle(BUFFER_SIZE, CACHE_SIZE);
			long transactionID = dbh.startTransaction();
			Schema schema =
				new Schema(1, "Key", new Field[] { IntField.INSTANCE }, new String[] { "Value" });
			Table table = dbh.createTable("Test", schema);
			DBRecord record = schema.createRecord(0);
			System.out.print("building database...");
			for (int i = 0; i < 1000000; i++) {
				record.setKey(i);
				record.setIntValue(0, i);
				table.putRecord(record);
			}
			timer.start("Iterating over 1000000 int records");
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				it.next();
			}
			timer.end();

			dbh.endTransaction(transactionID, true);
			dbh.close();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void testRandomAccess(TestTimer timer) {
		try {
			DBHandle dbh = new DBHandle(BUFFER_SIZE, CACHE_SIZE);
			long transactionID = dbh.startTransaction();
			Schema schema =
				new Schema(1, "Key", new Field[] { IntField.INSTANCE }, new String[] { "Value" });
			Table table = dbh.createTable("Test", schema);
			DBRecord record = schema.createRecord(0);
			System.out.print("building database...");
			for (int i = 0; i < 1000000; i++) {
				record.setKey(i);
				record.setIntValue(0, i);
				table.putRecord(record);
			}
			Random random = new Random();
			timer.start("Randomly accessing 1000000 int records");
			for (int i = 0; i < 1000000; i++) {
				table.getRecord(random.nextInt(1000000));
			}
			timer.end();

			dbh.endTransaction(transactionID, true);
			dbh.close();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

}

class TestTimer {
	long start;

	void start(String testMsg) {
		System.out.print(testMsg + "... ");
		start = System.currentTimeMillis();
	}

	void end() {
		long end = System.currentTimeMillis();
		System.out.println("" + (end - start) / 1000.0 + " seconds");
	}
}
