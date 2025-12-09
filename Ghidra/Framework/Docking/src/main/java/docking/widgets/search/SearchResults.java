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
package docking.widgets.search;

import java.net.URL;
import java.time.Duration;
import java.util.List;
import java.util.function.BooleanSupplier;

import docking.widgets.FindDialog;
import docking.widgets.SearchLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.MonitoredRunnable;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Job;
import ghidra.util.worker.Worker;

/**
 * A collection of {@link SearchLocation}s created when the user has performed a find operation on 
 * the {@link FindDialog}.  The dialog will find all results and then use the results to move to the 
 * next and previous locations as requested.  The user may also choose to show all results in a 
 * table.  
 * <p>
 * The searcher uses a worker queue to manage activating and deactivating highlights, which may 
 * require reload operations on the originally searched text.
 */
public abstract class SearchResults {

	private Worker worker;

	protected SearchResults(Worker worker) {
		this.worker = worker;
	}

	Worker getWorker() {
		return worker;
	}

//=================================================================================================
// Abstract Methods
//=================================================================================================	

	/**
	 * Returns the name of this set of search results.  This is a short description, such as a 
	 * filename or function name.  This should be null for text components that do not change 
	 * contents based on some external source of data, such as a file. 
	 * @return the name or null
	 */
	public abstract String getName();

	/**
	 * Activates this set of search results.  This will restore highlights to the source of the 
	 * search.
	 */
	public abstract void activate();

	/**
	 * Deactivates this set of search results.  This will clear this results' highlights from the 
	 * source of the search.
	 */
	public abstract void deactivate();

	/**
	 * Sets the active location, which will be highlighted differently than the other search 
	 * matches.  This method will ensure that this search results object is active (see 
	 * {@link #activate()}.  This method will also move the cursor to the given location.
	 * 
	 * @param location the location
	 */
	public abstract void setActiveLocation(SearchLocation location);

	/**
	 * {@return the active search location or null.  The active location is typically the search
	 * location that contains the user's cursor.}
	 */
	public abstract SearchLocation getActiveLocation();

	/**
	* Returns all search locations in this set of search results
	* @return the location
	*/
	public abstract List<SearchLocation> getLocations();

	public abstract boolean isEmpty();

	public abstract void dispose();

//=================================================================================================
// End Abstract Methods
//=================================================================================================	

	protected String getFilename(URL url) {
		if (url == null) {
			return null;
		}

		String path = url.getPath();
		int index = path.lastIndexOf('/');
		if (index < 0) {
			return null;
		}
		return path.substring(index + 1); // +1 to not get the slash
	}

	/**
	 * Clears all jobs that have the same class as the given job.  Clients can call this method 
	 * before submitting the given job to clear any other instances of that job type before running.
	 * @param job the job
	 */
	protected void cancelAllJobsOfType(FindJob job) {
		Class<? extends FindJob> clazz = job.getClass();
		worker.clearAllJobs(j -> j.getClass() == clazz);
	}

	/**
	 * Runs the given activation job.  This class will cancel any existing activation jobs with the
	 * assumption that only one activation should be taking place at any given time.  This is useful
	 * since activations may be slow.
	 * @param job the job
	 */
	protected void runActivationJob(ActivationJob job) {
		cancelAllJobsOfType(job);
		runJob(job);
	}

	/**
	 * Schedules the given job to run. This does not cancel any other pending work.
	 * @param job the job
	 */
	protected void runJob(FindJob job) {
		worker.schedule(job);
	}

	/**
	 * A worker {@link Job} that allows subclasses to add follow-on jobs to be performed as long
	 * as the work is not cancelled.
	 */
	protected class FindJob extends Job {

		// The parent job in a chain of jobs.  Useful for debugging. 
		protected FindJob parent;

		// optional follow-on job
		protected FindJob nextJob;

		// optional runnable to be called instead of doRun()
		protected MonitoredRunnable runnable;

		public FindJob() {
			// no runnable; use doRun()
		}

		public FindJob(FindJob parent) {
			this.parent = parent;
		}

		public FindJob(FindJob parent, MonitoredRunnable r) {
			this.parent = parent;
			this.runnable = r;
		}

		@Override
		public final void run(TaskMonitor monitor) throws CancelledException {
			monitor.checkCancelled();

			if (runnable != null) {
				runnable.monitoredRun(monitor);
			}
			else {
				doRun(monitor);
			}

			monitor.checkCancelled();

			if (nextJob != null) {
				nextJob.run(monitor);
			}
		}

		@SuppressWarnings("unused") // we don't use the cancel, but subclasses may
		protected void doRun(TaskMonitor monitor) throws CancelledException {
			// clients override to do background work
		}

		public FindJob thenRun(MonitoredRunnable r) {
			FindJob job = new FindJob(this, r);
			setNextJob(job);
			return this;
		}

		public FindJob thenWait(BooleanSupplier waitFor, Duration maxWaitTime) {
			FindJob job = new WaitJob(this, waitFor, maxWaitTime);
			setNextJob(job);
			return this;
		}

		public FindJob thenRunSwing(Runnable r) {
			MonitoredRunnable swingRunnable = m -> {
				Swing.runNow(() -> {
					if (m.isCancelled()) {
						return;
					}
					r.run();
				});
			};

			FindJob job = new FindJob(this, swingRunnable);
			setNextJob(job);

			return this;
		}

		private void setNextJob(FindJob job) {
			if (nextJob == null) {
				nextJob = job;
			}
			else {
				nextJob.setNextJob(job);
			}
		}

		@Override
		public String toString() {
			String base = getClass().getSimpleName() + ' ' + SearchResults.this;
			if (runnable != null) {
				return "runnable-only " + base;
			}
			return base;
		}
	}

	public class ActivationJob extends FindJob {
		// nothing special to do here; just a marker class
	}

	public class SwingJob extends FindJob {
		public SwingJob(Runnable r) {
			this.runnable = m -> Swing.runNow(r);
		}
	}

	private class WaitJob extends FindJob {
		private BooleanSupplier waitFor;
		private Duration maxWaitTime;

		protected WaitJob(FindJob parent, BooleanSupplier waitFor, Duration maxWaitTime) {
			super(parent);
			this.waitFor = waitFor;
			this.maxWaitTime = maxWaitTime;
		}

		@Override
		protected void doRun(TaskMonitor monitor) throws CancelledException {
			int sleepyTime = 250;
			int totalMs = 0;
			while (totalMs < maxWaitTime.toMillis()) {

				monitor.checkCancelled();

				if (waitFor.getAsBoolean()) {
					return;
				}

				totalMs += sleepyTime;
				sleep(sleepyTime);
			}

			monitor.cancel();
			throw new CancelledException();
		}

		private void sleep(int sleepyTime) throws CancelledException {

			try {
				Thread.sleep(sleepyTime);
			}
			catch (InterruptedException e) {
				Msg.debug(this, "Find job interrupted while waiting");
				throw new CancelledException();
			}
		}
	}
}
