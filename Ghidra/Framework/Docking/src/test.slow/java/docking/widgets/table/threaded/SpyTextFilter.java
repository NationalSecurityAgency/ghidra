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
package docking.widgets.table.threaded;

import java.util.concurrent.atomic.AtomicInteger;

import docking.widgets.filter.TextFilter;
import docking.widgets.table.RowFilterTransformer;
import docking.widgets.table.TableTextFilter;
import ghidra.docking.spy.SpyEventRecorder;

public class SpyTextFilter<T> extends TableTextFilter<T> {

	private volatile boolean hasFiltered = false;
	private AtomicInteger filterCount = new AtomicInteger(0);
	private SpyEventRecorder recorder;

	SpyTextFilter(TextFilter textFilter, RowFilterTransformer<T> transformer) {
		this(textFilter, transformer, new SpyEventRecorder("Stub"));
	}

	SpyTextFilter(TextFilter textFilter, RowFilterTransformer<T> transformer,
			SpyEventRecorder recorder) {
		super(textFilter, transformer);
		this.recorder = recorder;
		recorder.record("Created new " + getClass().getSimpleName());
	}

	@Override
	public boolean acceptsRow(T rowObject) {

		filterCount.incrementAndGet();

		if (!hasFiltered) {
			recorder.record("Model - filter started");
		}
		hasFiltered = true;
		return super.acceptsRow(rowObject);
	}

	boolean hasFiltered() {
		return hasFiltered;
	}

	int getFilterCount() {
		return filterCount.get();
	}

	void reset() {
		recorder.record("Test - filter spy reset");
		hasFiltered = false;
		filterCount.set(0);
	}

	void dumpEvents() {
		recorder.dumpEvents();
	}
}
