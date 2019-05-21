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
package ghidra.graph.job;

import java.util.*;

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.QueueStub;
import ghidra.util.exception.AssertException;
import utility.function.Callback;

/**
 * A class to run {@link GraphJob}s.  This class will queue jobs and will run them
 * in the Swing thread.  Job implementations may be multi-threaded, as they choose, by managing
 * threads themselves.    This is different than a typical job runner, which is usually
 * itself threaded.
 * <P>
 * A job is considered finished when {@link #jobFinished(GraphJob)}
 * is called on this class.  After this callback, the next job will be run.  
 * <P>
 * {@link #setFinalJob(GraphJob)} sets a job to be run last, after all jobs in the queue
 * have finished.
 * 
 * <P>When a job is added via {@link #schedule(GraphJob)}, any currently running job will 
 * be told to finish immediately, if it's {@link GraphJob#canShortcut()} returns true.  If it 
 * cannot be shortcut, then it will be allowed to finish.  Further, this logic will be applied
 * to each job in the queue.  So, if there are multiple jobs in the queue, which all return
 * true for {@link GraphJob#canShortcut()}, then they will each be shortcut (allowing them 
 * to complete) before running the newly scheduled job.
 * 
 * <P>This class is thread-safe in that you can {@link #schedule(GraphJob)} jobs from any
 * thread.
 * 
 * <P>Synchronization Policy:  the methods that mutate fields of this class or read them 
 * must be synchronized.
 */
public class GraphJobRunner implements GraphJobListener {

	private Queue<GraphJob> queue = new LinkedList<>();
	private GraphJob finalJob;
	private GraphJob currentJob;

	private boolean isShortcutting = false;

	public void schedule(GraphJob job) {

		trace("schedule() - " + job);

		Objects.requireNonNull(job, "Graph job cannot be null");

		if (job.isFinished()) {
			throw new IllegalArgumentException("cannot schedule a finished job!");
		}

		queue.add(job);
		swing(this::shortCutAndRunNextJob);
	}

	private void swing(Runnable r) {
		SystemUtilities.runIfSwingOrPostSwingLater(r);
	}

	/**
	 * Sets a job to run after all currently running and queued jobs.  If a final job was already
	 * set, then that job will be replaced with the given job.
	 * 
	 * @param job the job to run
	 */
	public synchronized void setFinalJob(GraphJob job) {

		trace("setFinalJob() - " + job);

		if (job.isFinished()) {
			throw new IllegalArgumentException("cannot schedule a finished job!");
		}

		// simply overwrite any pending final job, as we can only have one 
		finalJob = Objects.requireNonNull(job, "Graph job cannot be null");
		swing(this::maybeRunNextJob);
	}

	public synchronized boolean isBusy() {
		if (!queue.isEmpty()) {
			return true;
		}

		if (finalJob != null) {
			return true;
		}

		return currentJob != null;
	}

	/*for testing*/ synchronized GraphJob getCurrentJob() {
		return currentJob;
	}

	/**
	 * Causes all jobs to be finished as quickly as possible, calling {@link GraphJob#shortcut()}
	 * on each job.   
	 * 
	 * <P>Note: some jobs are not shortcut-able and will finish on their own time.  Any jobs 
	 * queued behind a non-shortcut-able job will <b>not</b> be shortcut. 
	 * 
	 * @see #dispose()
	 */
	public void finishAllJobs() {
		swing(this::shortCutAll);
	}

	/**
	 * Clears any pending jobs, stops the currently running job ungracefully and updates this
	 * class so that any new jobs added will be ignored.
	 */
	public synchronized void dispose() {
		trace("dispose()");
		clearAllJobs();
		queue = new QueueStub<>();
	}

	private synchronized void clearAllJobs() {
		trace("clearAllJobs()");
		finalJob = null;
		Queue<GraphJob> oldQueue = queue;
		queue = new QueueStub<>();
		oldQueue.clear();

		trace("\tcurrent job: " + currentJob);
		if (currentJob != null) {
			currentJob.dispose();
		}
		currentJob = null;
	}

	@Override
	public void jobFinished(GraphJob job) {
		String methodName = "jobFinished()";
		trace(methodName + " " + job);
		SystemUtilities.assertThisIsTheSwingThread(
			"jobFinished() must be called in the Swing thread.");
		synchronized (this) {
			if (currentJob != null && job != currentJob) {
				throw new AssertException(
					"Received a callback from a job that is not my current job! Current job: " +
						currentJob + " and finished job: " + job);
			}

			trace("\t" + methodName + " setting currentJob to null");
			currentJob = null;
			maybeRunNextJob();
		}
	}

	/**
	 * Shortcut as many jobs as possible to clear the queue and then trigger the run of the 
	 * remaining jobs.
	 */
	private synchronized void shortCutAndRunNextJob() {

		String methodName = "shortcut()";
		trace(methodName + " - currentJob?: " + currentJob);

		if (queue.isEmpty()) {
			trace("\t" + methodName + " no pending jobs; leaving");
			// nothing to shortcut (leave any current job running when there are none waiting)
			return;
		}

		performShortcutFunction(() -> {
			shortcutAsMuchAsPossible(false);
		});

		// 
		// Run whatever is left
		//
		trace("\t" + methodName + " at end; calling runNextJob()");
		maybeRunNextJob();
	}

	private synchronized void shortCutAll() {

		String methodName = "shortcutAll()";
		trace(methodName + " - currentJob?: " + currentJob);

		performShortcutFunction(() -> {
			boolean allWereShortcut = shortcutAsMuchAsPossible(true);
			trace("\t\twere all jobs shortcut? " + allWereShortcut);
			if (allWereShortcut) {
				shortcutFinalJob();
			}
		});
	}

	private void performShortcutFunction(Callback callback) {
		isShortcutting = true;
		trace("\tset isShortcutting = true");
		try {
			callback.call();
		}
		finally {
			isShortcutting = false;
			trace("\t\tset isShortcutting = false");
		}
	}

	private boolean shortcutAsMuchAsPossible(boolean shortcutAll) {

		//
		// See if we can shortcut the current job 
		//
		if (!shortcutCurrentJob()) {
			// cannot stop the current job; allow it to finish, processing the pending jobs later
			return false;
		}

		if (!shortcutPendingJobs(shortcutAll)) {
			return false;
		}

		return true;
	}

	/**
	 * Attempts to shortcut the currently running job, if there is one
	 * 
	 * @return false if there is a currently running job that cannot be shortcut
	 */
	private boolean shortcutCurrentJob() {

		String methodName = "shortcutCurrentJob()";

		if (currentJob == null) {
			return true; // nothing to do
		}

		if (!currentJob.canShortcut()) {
			// can't stop the current job--let it go
			trace("\t" + methodName + " current job cannot be shortcut; leaving");
			return false;
		}

		trace("\t" + methodName + " calling shortcut on current job: " + currentJob);

		// the shortcut() may trigger a callback to set the currentJob; we don't want to null
		// out the current job if it is changed, but we do if it is not
		GraphJob job = currentJob;
		currentJob = null;
		job.shortcut();
		trace("\t\t" + methodName + " after calling shortcut on current job: " + job);
		return true;
	}

	private boolean shortcutPendingJobs(boolean shortcutAll) {
		//
		// Attempt to shortcut the remaining items in the queue that we can shortcut, optionally 
		// leaving the last job. (The last job is the most recently added and 
		// presumably the one the client wants us to run.)
		//
		String methodName = "shortcutPendingJobs()";
		trace("\t" + methodName + " queued job count: " + queue.size());
		int limit = shortcutAll ? 0 : 1;
		while (queue.size() > limit) {
			GraphJob nextJob = queue.peek();
			if (!nextJob.canShortcut()) {
				// can't stop the next job--leave it to be run later
				trace("\t" + methodName + " found pending job; cannot shortcut: " + nextJob);
				return false;
			}

			nextJob = queue.poll();
			trace("\t" + methodName + " calling shortcut on pending job: " + nextJob);
			nextJob.shortcut();
			trace("\t\t" + methodName + " after calling shortcut on pending job: " + nextJob);
		}
		return true;
	}

	private void shortcutFinalJob() {
		trace("shortcutFinalJob() - " + finalJob);
		if (finalJob != null && finalJob.canShortcut()) {
			finalJob.shortcut();
			finalJob = null;
		}
	}

	private synchronized void maybeRunNextJob() {
		String methodName = "maybeRunNextJob()";
		trace(methodName);

		if (isShortcutting) {
			trace("\t" + methodName + " shortcutting the queue - not running the next job " +
				currentJob);
			return;
		}

		trace("\t" + methodName + " currentJob: " + currentJob);
		if (currentJob != null) {
			trace("\t" + methodName + " is it finished?: " + currentJob.isFinished());
			// sanity check!
			if (currentJob.isFinished()) {
				throw new IllegalStateException("The following job did not call jobFinished() " +
					"after performing its work: " + currentJob);
			}

			// do nothing if a job is running
			trace("\t" + methodName + " not running another job; current job is not finished");
			return;
		}

		GraphJob nextJob = queue.poll();
		if (nextJob != null) {
			trace("\t" + methodName + " setting currentJob to: " + nextJob + " and last job: " +
				currentJob);
			currentJob = nextJob;
			currentJob.execute(this);
			return;
		}

		if (finalJob != null) {
			trace("\t" + methodName + " setting currentJob to final job: " + finalJob +
				" and last job: " + currentJob);
			currentJob = finalJob;
			finalJob = null;
			currentJob.execute(this);
		}
	}

	private void trace(String message) {
		Msg.trace(this, message);
	}
}
