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
package docking.widgets.timeline;

import static org.junit.Assert.assertEquals;

import java.awt.event.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;

import javax.swing.JFrame;
import javax.swing.JScrollPane;

import org.junit.Before;
import org.junit.Test;

import com.google.common.collect.Range;

import docking.widgets.table.DefaultEnumeratedColumnTableModel;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import docking.widgets.table.EnumeratedColumnTableModel;

public class TimelinePanelTest {
	protected static class MyRow {
		private final String name;
		private Range<Integer> lifespan;

		public MyRow(String name, Range<Integer> lifespan) {
			this.name = name;
			this.lifespan = lifespan;
		}

		public String getName() {
			return name;
		}

		public Range<Integer> getLifespan() {
			return lifespan;
		}

		public void setLifespan(Range<Integer> lifespan) {
			this.lifespan = lifespan;
		}

		@Override
		public String toString() {
			return name;
		}
	}

	protected enum MyColumns implements EnumeratedTableColumn<MyColumns, MyRow> {
		NAME("Name", String.class, MyRow::getName),
		BIRTH("Lifespan", Range.class, MyRow::getLifespan);

		private String header;
		private Class<?> cls;
		private Function<MyRow, ?> getter;

		private <T> MyColumns(String header, Class<T> cls, Function<MyRow, T> getter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(MyRow row) {
			return getter.apply(row);
		}

		@Override
		public String getHeader() {
			return header;
		}
	}

	private JFrame window;
	private EnumeratedColumnTableModel<MyRow> model;
	private TimelinePanel<MyRow, ?> timeline;

	protected void inspect() {
		window.setBounds(0, 0, 1000, 200);
		CompletableFuture<Void> windowClosed = new CompletableFuture<>();
		WindowListener listener = new WindowAdapter() {
			@Override
			public void windowClosed(WindowEvent e) {
				windowClosed.complete(null);
			}
		};
		window.addWindowListener(listener);
		window.setVisible(true);
		try {
			windowClosed.get();
		}
		catch (InterruptedException | ExecutionException e) {
			// Whatever 
		}
		finally {
			window.removeWindowListener(listener);
		}
	}

	@Before
	public void setUp() {
		window = new JFrame();
		model = new DefaultEnumeratedColumnTableModel<>("People", MyColumns.class);
		timeline = new TimelinePanel<>(model, MyRow::getLifespan);
		window.add(new JScrollPane(timeline));
	}

	@Test
	public void testEmpty() {
		assertEquals(0, timeline.tracks.size());
		assertEquals(0, timeline.trackMap.size());
	}

	@Test
	public void testSingleItemClosed() {
		model.add(new MyRow("Albert", Range.closed(1879, 1955)));

		assertEquals(1, timeline.tracks.size());
		assertEquals(1, timeline.trackMap.size());
		assertEquals(1, timeline.tracks.get(0).objects.asMapOfRanges().size());
	}

	@Test
	public void testTwoItemsOneTrack() {
		model.add(new MyRow("Albert", Range.closed(1879, 1955)));
		model.add(new MyRow("Bob", Range.atLeast(1956)));

		assertEquals(1, timeline.tracks.size());
		assertEquals(2, timeline.trackMap.size());
		assertEquals(2, timeline.tracks.get(0).objects.asMapOfRanges().size());
	}

	@Test
	public void testTwoItemsTwoTracks() {
		model.add(new MyRow("Albert", Range.closed(1879, 1955)));
		model.add(new MyRow("Bill", Range.atLeast(1955)));

		assertEquals(2, timeline.tracks.size());
		assertEquals(2, timeline.trackMap.size());
		assertEquals(1, timeline.tracks.get(0).objects.asMapOfRanges().size());
		assertEquals(1, timeline.tracks.get(1).objects.asMapOfRanges().size());
	}

	@Test
	public void testTwoItemsOneTrackMixedBounds() {
		model.add(new MyRow("Albert", Range.closed(1879, 1955)));
		model.add(new MyRow("Bill", Range.greaterThan(1955)));

		assertEquals(1, timeline.tracks.size());
		assertEquals(2, timeline.trackMap.size());
		assertEquals(2, timeline.tracks.get(0).objects.asMapOfRanges().size());
	}

	@Test
	public void testTwoItemsThenClear() {
		model.add(new MyRow("Albert", Range.closed(1879, 1955)));
		model.add(new MyRow("Bill", Range.atLeast(1955)));
		model.clear();

		assertEquals(0, timeline.tracks.size());
		assertEquals(0, timeline.trackMap.size());
	}

	@Test
	public void testTwoItemsTwoTracksRemoveOne() {
		model.add(new MyRow("Albert", Range.closed(1879, 1955)));
		model.add(new MyRow("Bill", Range.atLeast(1955)));
		model.deleteWith(row -> row.getLifespan().contains(1900));

		assertEquals(1, timeline.tracks.size());
		assertEquals(1, timeline.trackMap.size());
		assertEquals(1, timeline.tracks.get(0).objects.asMapOfRanges().size());
	}

	@Test
	public void testTwoItemsOneTrackUpdateRequiresTwo() {
		model.add(new MyRow("Albert", Range.closed(1879, 1955)));
		MyRow elvis = new MyRow("Elvis", Range.closed(1935, 1977));
		model.add(elvis);
		elvis.setLifespan(Range.atLeast(1935));
		model.notifyUpdated(elvis);

		assertEquals(2, timeline.tracks.size());
		assertEquals(2, timeline.trackMap.size());
		assertEquals(1, timeline.tracks.get(0).objects.asMapOfRanges().size());
		assertEquals(1, timeline.tracks.get(1).objects.asMapOfRanges().size());
	}
}
