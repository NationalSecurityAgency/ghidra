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

import ghidra.docking.spy.SpyEventRecorder;

public class TestThreadedTableModelListener implements ThreadedTableModelListener {

	private volatile boolean pending;
	private volatile boolean updating;
	private volatile boolean completed;
	private volatile boolean cancelled;

	private SpyEventRecorder spy;
	private ThreadedTableModel<?, ?> model;

	public TestThreadedTableModelListener(ThreadedTableModel<?, ?> model) {
		this(model, new SpyEventRecorder("Listener Spy"));
	}

	public TestThreadedTableModelListener(ThreadedTableModel<?, ?> model, SpyEventRecorder spy) {
		this.spy = spy;
		this.model = model;
	}

	void reset(ThreadedTableModel<?, ?> newModel) {
		spy.record("Test - listener - reset()");
		completed = cancelled = false;
	}

	boolean doneWork() {
		spy.record("Test - listener - doneWork()? " + (completed || cancelled) + " - completed? " +
			completed + "; cancelled? " + cancelled);
		return completed || cancelled;
	}

	boolean startedWork() {
		spy.record("Test - listener - startedWork() - updating? " + updating);
		return updating;
	}

	@Override
	public void loadPending() {
		spy.record("Swing - listener - loadPending()");
		pending = true;
	}

	@Override
	public void loadingStarted() {
		spy.record("Swing - listener - loadStarted()");
		updating = true;
	}

	@Override
	public void loadingFinished(boolean wasCancelled) {
		spy.record("Swing - listener - loadingFinished() - cancelled? " + wasCancelled +
			"; size: " + model.getRowCount());
		cancelled = wasCancelled;
		completed = !cancelled;
	}

	@Override
	// @formatter:off
	public String toString() {
		return getClass().getSimpleName() + "[" +
			"pending="+ pending + 
			", updating=" + updating + 
			", completed=" + completed + 
			", cancelled=" + cancelled +
		"]";
	}
	// @formatter:on

}
