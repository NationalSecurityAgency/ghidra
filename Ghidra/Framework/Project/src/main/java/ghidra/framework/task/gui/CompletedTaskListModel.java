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
package ghidra.framework.task.gui;

import ghidra.framework.task.*;
import ghidra.util.task.SwingUpdateManager;

import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;

public class CompletedTaskListModel extends GTaskListModel<GTaskResultInfo> {
	private static final int MIN_DELAY = 250;
	private static final int MAX_DELAY = 1000;

	private static final int PRUNE_SIZE = 10;
	private static final int MAX_SIZE = 200;
	private List<GTaskResultInfo> list = new ArrayList<GTaskResultInfo>();
	private GTaskManager taskManager;
	private CompletedPanelTaskListener taskListener;
	private Queue<Runnable> runnableQueue = new ConcurrentLinkedQueue<Runnable>();
	private SwingUpdateManager updateManager;

	CompletedTaskListModel(GTaskManager taskMgr) {
		this.taskManager = taskMgr;
		taskListener = new CompletedPanelTaskListener();
		updateManager = new SwingUpdateManager(MIN_DELAY, MAX_DELAY, new Runnable() {
			@Override
			public void run() {

				while (!runnableQueue.isEmpty()) {
					Runnable runnable = runnableQueue.poll();
					runnable.run();
				}
			}
		});

		taskMgr.addTaskListener(taskListener);
	}

	public void dispose() {
		taskManager.removeTaskListener(taskListener);
	}

	@Override
	public int getSize() {
		return list.size();
	}

	@Override
	public GTaskResultInfo getElementAt(int index) {
		return list.get(index);
	}

	private void pruneList() {
		if (list.size() > MAX_SIZE) {
			list.subList(0, PRUNE_SIZE).clear();
			fireIntervalRemoved(0, PRUNE_SIZE - 1);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class CompletedTaskRunnable implements Runnable {
		private GTaskResult result;

		CompletedTaskRunnable(GTaskResult result) {
			this.result = result;
		}

		@Override
		public void run() {
			int startInterval = list.size();
			if (isNewTransaction()) {
				list.add(new GTaskResultInfo(null));
			}
			list.add(new GTaskResultInfo(result));
			fireIntervalAdded(startInterval, list.size() - 1);
			pruneList();
		}

		private boolean isNewTransaction() {
			if (list.isEmpty()) {
				return false;
			}
			GTaskResultInfo element = list.get(list.size() - 1);
			GTaskResult lastResult = element.getResult();
			if (lastResult == null) {
				return false;
			}
			return !lastResult.hasSameTransaction(result);
		}
	}

	private class InitializeRunnable implements Runnable {
		@Override
		public void run() {
			List<GTaskResult> taskResults = taskManager.getTaskResults();
			GTaskResult lastResult = null;
			for (GTaskResult gTaskResult : taskResults) {
				if (gTaskResult.hasSameTransaction(lastResult)) {
					list.add(new GTaskResultInfo(null));
				}
				list.add(new GTaskResultInfo(gTaskResult));
			}
		}
	}

	private class CompletedPanelTaskListener extends GTaskListenerAdapter {
		@Override
		public void taskCompleted(GScheduledTask task, GTaskResult result) {
			runnableQueue.add(new CompletedTaskRunnable(result));
			updateManager.update();
		}

		@Override
		public void initialize() {
			runnableQueue.add(new InitializeRunnable());
			updateManager.update();
		}
	}
}
