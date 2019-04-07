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
package ghidra.framework.main.logviewer.ui;

import java.io.File;
import java.nio.file.WatchService;
import java.util.concurrent.*;

import ghidra.framework.main.logviewer.event.FVEvent;
import ghidra.framework.main.logviewer.event.FVEvent.EventType;
import ghidra.framework.main.logviewer.event.FVEventListener;

/**
 * The FileWatcher *watches* a single file and fires a change notification whenever the file 
 * is modified. A couple notes:
 * 
 * 1. To keep from processing change events every time the file is modified, which may be
 *    too frequent and cause processing issues, we use a simple polling mechanism.  
 *    
 * 2. Changes in the file are identified by inspecting the {@link File#lastModified()}
 *    timestamp. 
 * 
 * 3. The {@link WatchService} mechanism is not being used here since we cannot specify a 
 *    polling rate.
 */
public class FileWatcher {

	private long timestamp = -1;
	private final int POLLING_INTERVAL_SEC = 5;
	private final int POLLING_DELAY_SEC = 0;

	private File file;
	private ScheduledFuture<?> future;
	private ScheduledExecutorService executor;

	private FVEventListener eventListener;

	/**
	 * Constructor. Creates a new {@link Executor} that will inspect the file at regular 
	 * intervals.  Users must call {@link #start()} to begin polling.
	 * 
	 * @param file the file to be watched
	 */
	public FileWatcher(File file, FVEventListener eventListener) {
		this.file = file;
		this.eventListener = eventListener;
		executor = Executors.newSingleThreadScheduledExecutor();
	}

	/**
	 * Suspends the timer so it will no longer poll. This does not perform a shutdown, so the
	 * future may be scheduled again.
	 */
	public void stop() {
		future.cancel(false);
	}

	/**
	 * Starts polling, or resumes polling if previously stopped.
	 */
	public void start() {

		if (executor == null) {
			return;
		}

		future = executor.scheduleAtFixedRate(new Runnable() {

			@Override
			public void run() {

				// Always check for cancel here.  When the user closes the window we call cancel
				// on the service, but that doesn't actually cancel the task, it just ensures
				// that any call to isCancelled returns true.
				if (future.isCancelled()) {
					return;
				}
				if (isFileUpdated(file)) {
					FVEvent updateEvt = new FVEvent(EventType.FILE_CHANGED, null);
					eventListener.send(updateEvt);
				}
			}

		}, POLLING_DELAY_SEC, POLLING_INTERVAL_SEC, TimeUnit.SECONDS);
	}

	/**
	 * Checks the timestamp of the given file to see if it has changed.  If so, returns true.
	 * 
	 * @param file
	 * @return
	 */
	private boolean isFileUpdated(File file) {

		// If the timestamp == -1, then this is the first time the timer has gone off, so ignore
		// it. This is here to keep from popping up a notification immediately after the file
		// has been brought up.
		if (timestamp == -1) {
			timestamp = file.lastModified();
			return false;
		}
		else if (timestamp != file.lastModified()) {
			timestamp = file.lastModified();
			return true;
		}

		return false;
	}
}
