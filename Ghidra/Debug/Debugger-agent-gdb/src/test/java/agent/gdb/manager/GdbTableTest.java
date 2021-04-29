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
package agent.gdb.manager;

import static org.junit.Assert.*;

import java.util.*;
import java.util.function.Consumer;

import org.junit.Test;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import agent.gdb.manager.GdbTable;
import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;

public class GdbTableTest {
	protected GdbMiFieldList buildFieldList(Consumer<GdbMiFieldList.Builder> conf) {
		GdbMiFieldList.Builder builder = GdbMiFieldList.builder();
		conf.accept(builder);
		return builder.build();
	}

	protected <K, V> Map<K, V> buildMap(Consumer<ImmutableMap.Builder<K, V>> conf) {
		ImmutableMap.Builder<K, V> builder = ImmutableMap.builder();
		conf.accept(builder);
		return builder.build();
	}

	protected <E> List<E> buildList(Consumer<ImmutableList.Builder<E>> conf) {
		ImmutableList.Builder<E> builder = ImmutableList.builder();
		conf.accept(builder);
		return builder.build();
	}

	protected GdbTable buildTestTable() {
		return new GdbTable(buildFieldList((data) -> {
			data.add("nr_rows", "3");
			data.add("nr_cols", "2");
			data.add("hdr", buildList((hdr) -> {
				hdr.add(buildFieldList((col) -> {
					col.add("col_name", "c0");
					col.add("colhdr", "First Column");
				}));
				hdr.add(buildFieldList((col) -> {
					col.add("col_name", "c1");
					col.add("colhdr", "Second Column");
				}));
			}));
			data.add("body", buildFieldList((body) -> {
				body.add("item", buildFieldList((item) -> {
					item.add("c0", "Col1Row1");
					item.add("c1", "Col2Row1");
				}));
				body.add("item", buildFieldList((item) -> {
					item.add("c1", "Col2Row2");
					item.add("c0", "Col1Row2");
				}));
				body.add("item", buildFieldList((item) -> {
					item.add("c0", "Col1Row3");
					item.add("c1", "Col2Row3");
				}));
			}));
		}), "item");
	}

	@Test
	public void testBuildGdbTable() {
		buildTestTable();
	}

	@Test
	public void testColumns() {
		GdbTable table = buildTestTable();
		assertEquals(2, table.columns().size());
		assertEquals(new LinkedHashSet<>(Arrays.asList("First Column", "Second Column")),
			table.columns().keySet());
	}

	@Test
	public void testRowCount() {
		GdbTable table = buildTestTable();
		assertEquals(3, table.rows().size());
		assertNotNull(table.rows().get(0));
		assertNotNull(table.rows().get(1));
		assertNotNull(table.rows().get(2));
		try {
			table.rows().get(3);
			fail();
		}
		catch (IndexOutOfBoundsException e) {
			// pass
		}
	}

	@Test
	public void testRowContents() {
		GdbTable table = buildTestTable();
		Map<String, String> row;

		row = table.rows().get(0);
		assertEquals(2, row.size());
		assertEquals(new HashSet<>(Arrays.asList("First Column", "Second Column")), row.keySet());
		assertEquals("Col1Row1", row.get("First Column"));
		assertEquals("Col2Row1", row.get("Second Column"));

		row = table.rows().get(1);
		assertEquals(2, row.size());
		assertEquals(new HashSet<>(Arrays.asList("First Column", "Second Column")), row.keySet());
		assertEquals("Col1Row2", row.get("First Column"));
		assertEquals("Col2Row2", row.get("Second Column"));

		row = table.rows().get(2);
		assertEquals(2, row.size());
		assertEquals(new HashSet<>(Arrays.asList("First Column", "Second Column")), row.keySet());
		assertEquals("Col1Row3", row.get("First Column"));
		assertEquals("Col2Row3", row.get("Second Column"));
	}

	@Test
	public void testRowIterator() {
		GdbTable table = buildTestTable();
		List<Map<String, String>> copied = new ArrayList<>();
		for (Map<String, String> row : table.rows()) {
			copied.add(new LinkedHashMap<>(row));
		}
		assertEquals(buildList((expTable) -> {
			expTable.add(buildMap((row) -> {
				row.put("First Column", "Col1Row1");
				row.put("Second Column", "Col2Row1");
			}));
			expTable.add(buildMap((row) -> {
				row.put("First Column", "Col1Row2");
				row.put("Second Column", "Col2Row2");
			}));
			expTable.add(buildMap((row) -> {
				row.put("First Column", "Col1Row3");
				row.put("Second Column", "Col2Row3");
			}));
		}), copied);
	}

	@Test
	public void testColumnIterator() {
		GdbTable table = buildTestTable();
		Map<String, List<String>> copied = new LinkedHashMap<>();
		for (Map.Entry<String, List<String>> col : table.columns().entrySet()) {
			copied.put(col.getKey(), new ArrayList<>(col.getValue()));
		}
		assertEquals(buildMap((expTable) -> {
			expTable.put("First Column", buildList((col) -> {
				col.add("Col1Row1");
				col.add("Col1Row2");
				col.add("Col1Row3");
			}));
			expTable.put("Second Column", buildList((col) -> {
				col.add("Col2Row1");
				col.add("Col2Row2");
				col.add("Col2Row3");
			}));
		}), copied);
	}
}
