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

import java.util.List;

import generic.concurrent.QProgressListener;
import ghidra.docking.spy.SpyEventRecorder;

public class ThreadedTableModelWorkerListener<T> implements QProgressListener<T> {

	private SpyEventRecorder spy;
	private ThreadedTableModel<T, Object> model;

	ThreadedTableModelWorkerListener(SpyEventRecorder spy, ThreadedTableModel<T, Object> model) {
		this.spy = spy;
		this.model = model;
	}

	@Override
	public void progressChanged(long id, T item, long progress) {
		spy.record("Table Queue - progressChanged() - " + item + "; progress: " + progress);
	}

	@Override
	public void taskStarted(long id, T item) {
		spy.record("Table Queue - taskStarted() - " + item);
	}

	@Override
	public void taskEnded(long id, T item, long totalCount, long completedCount) {
		spy.record(
			"Table Queue - taskEnded() - " + item + "; total submitted items: " + totalCount);
		dumpModel();
	}

	@Override
	public void progressModeChanged(long id, T item, boolean indeterminate) {
		spy.record("Table Queue - progressModeChanged() - " + item + "; is indeterminate: " +
			indeterminate);
	}

	@Override
	public void maxProgressChanged(long id, T item, long maxProgress) {
		spy.record(
			"Table Queue - maxProgressChanged() - " + item + "; max progress: " + maxProgress);
	}

	@Override
	public void progressMessageChanged(long id, T item, String message) {
		spy.record("Table Queue - progressMessageChanged() - " + item + "; message: " + message);
	}

	private void dumpModel() {
		List<T> allData = model.getAllData();
		StringBuilder buffy = new StringBuilder("\n\tRow count: " + allData.size());
		for (T t : allData) {
			buffy.append("\trow value: ").append(t.toString()).append('\n');
		}
		spy.record(buffy.toString());
	}
}
