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
package docking.widgets.table;

import static org.junit.Assert.*;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.*;

import org.junit.Test;

import ghidra.util.task.TaskMonitor;

public class GTableCSVTest {

	@Test
	public void testCSV_QuotesGetEscaped() {

		AnyObjectTableModel<CSVRowObject> model =
			new AnyObjectTableModel<>("MyModel", CSVRowObject.class,
				"getName", "getDescription", "getNumber");

		//@formatter:off
		List<CSVRowObject> data = Arrays.asList(
			new CSVRowObject("Bob", "Bobby", 11),
			new CSVRowObject("Joan", "Joan has \"quoted\" text", 0),
			new CSVRowObject("Sam", "\"Sam has a single quote text", 23),
			new CSVRowObject("Time", "Tim is last", 33)
		);
		//@formatter:on
		model.setModelData(data);

		GTable table = new GTable(model);
		List<Integer> columns = new ArrayList<>();

		PrintWriterSpy writer = new PrintWriterSpy();
		GTableToCSV.writeCSV(writer, table, columns, TaskMonitor.DUMMY);

		assertRowValues(data, writer);
	}

	@Test
	public void testCSV_CommasGetEscaped() {

		AnyObjectTableModel<CSVRowObject> model =
			new AnyObjectTableModel<>("MyModel", CSVRowObject.class,
				"getName", "getDescription", "getNumber");

		//@formatter:off
		List<CSVRowObject> data = Arrays.asList(
			new CSVRowObject("Bob", "Bobby", 11),
			new CSVRowObject("Joan", "Joan has a comma, in her text", 0),
			new CSVRowObject("Sam", ",Sam has a leading comma", 23),
			new CSVRowObject("Time", "Tim is last", 33)
		);
		//@formatter:on
		model.setModelData(data);

		GTable table = new GTable(model);
		List<Integer> columns = new ArrayList<>();

		PrintWriterSpy writer = new PrintWriterSpy();
		GTableToCSV.writeCSV(writer, table, columns, TaskMonitor.DUMMY);

		assertRowValues(data, writer);
	}

	private void assertRowValues(List<CSVRowObject> data, PrintWriterSpy writer) {

		String results = writer.toString();
		String[] lines = results.split("\n");
		for (int i = 1; i < lines.length; i++) {
			int index = i - 1; // the first line is the header
			CSVRowObject row = data.get(index);
			String line = lines[i];
			String[] columns = line.split("(?<!\\\\),");

			String name = columns[0].replaceAll("\\\\,", ",");
			name = name.replaceAll("\\\\\"", "\"");
			assertEquals("\"" + row.getName() + "\"", name);

			String description = columns[1].replaceAll("\\\\,", ",");
			description = description.replaceAll("\\\\\"", "\"");
			assertEquals("\"" + row.getDescription() + "\"", description);

			String number = columns[2].replaceAll("\\\\,", ",");
			number = number.replaceAll("\\\\\"", "\"");
			assertEquals("\"" + row.getNumber() + "\"", number);
		}
	}

	class CSVRowObject {

		private String name;
		private String description;
		private int number;

		CSVRowObject(String name, String description, int number) {
			this.name = name;
			this.description = description;
			this.number = number;
		}

		public String getName() {
			return name;
		}

		public String getDescription() {
			return description;
		}

		public int getNumber() {
			return number;
		}
	}

	private class PrintWriterSpy extends PrintWriter {

		private StringWriter stringWriter;

		PrintWriterSpy() {
			super(new StringWriter(), true);
			stringWriter = ((StringWriter) out);
		}

		@Override
		public String toString() {
			return stringWriter.toString();
		}
	}
}
