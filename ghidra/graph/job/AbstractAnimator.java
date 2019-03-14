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


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.TimingTargetAdapter;

import ghidra.util.exception.AssertException;
import ghidra.util.task.BusyListener;

public abstract class AbstractAnimator {

	private Logger log = LogManager.getLogger(AbstractAnimator.class);

	protected Animator animator;
	private boolean hasFinished; // flag to signal not to repeatedly call finish
	private BusyListener busyListener;

	protected abstract Animator createAnimator();

	/**
	 * A callback given when this animator has run to completion.  This will be called whether
	 * the animator is stopped prematurely or ends naturally.
	 */
	protected abstract void finished();

	public void setBusyListener(BusyListener listener) {
		this.busyListener = listener;
	}

	protected void followOnAnimatorScheduled() {
		trace("followOnAnimatorScheduled");
		stopMe();
	}

	public void start() {
		trace("start() - " + getClass().getSimpleName());

		validateNotFinished();

		animator = createAnimator();

		trace("\tcreated animator - " + animator);
		if (animator == null) {
			callFinish();
			return;
		}

		if (busyListener != null) {
			animator.addTarget(new TimingTargetAdapter() {
				@Override
				public void begin() {
					busyListener.setBusy(true);
				}

				@Override
				public void end() {
					busyListener.setBusy(false);
				}
			});
		}

		animator.addTarget(new TimingTargetAdapter() {
			@Override
			public void end() {
				callFinish();
			}
		});

		// this can happen if some external force calls stop() on this animator while it
		// is building itself
		validateNotFinished();

		animator.start();
	}

	private void validateNotFinished() {
		trace("validateNotFinished()");

		if (hasFinished) {
			trace("\talready finished - programming error!");
			throw new AssertException("Called start() on an animator that has already " +
				"finished!  Animator: " + getClass().getSimpleName());
		}
	}

	private void callFinish() {
		trace("callFinish()");
		if (hasFinished) {
			trace("\talready finished");
			return; // already called 
		}
		hasFinished = true;

		finished();
	}

	/**
	 * Stops this animator <b>and all scheduled animators!</b>
	 */
	public void stop() {
		trace("stop()");
		stopMe();
	}

	protected void stopMe() {
		trace("stopMe()");
		if (animator == null) {
			hasFinished = true;
			return;
		}

		animator.stop();
	}

	public boolean isRunning() {
		trace("isRunning()");
		if (amIRunning()) {
			trace("\tstill running");
			return true;
		}

		return false;
	}

	public boolean hasFinished() {
		return hasFinished;
	}

	private boolean amIRunning() {
		trace("amIRunning()");
		if (animator == null) {
			return false;
		}

		return animator.isRunning();
	}

	protected void trace(String message) {
		log.trace(message + " " + getClass().getSimpleName() + " (" +
			System.identityHashCode(this) + ")\t");
	}
}
