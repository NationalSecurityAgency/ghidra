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

import ghidra.util.Msg;
import ghidra.util.task.BusyListener;

public abstract class AbstractAnimatorJob implements GraphJob {

	/**
	 * A somewhat arbitrary vertex count past which not to animate actions that are intensive.
	 */
	public static final int TOO_BIG_TO_ANIMATE = 125;

	protected Logger log = LogManager.getLogger(AbstractAnimator.class);

	private boolean isFinished;
	private BusyListener busyListener;
	protected Animator animator;
	protected boolean isShortcut;

	private GraphJobListener finishedListener;

	protected abstract Animator createAnimator();

	/**
	 * A callback given when this animator has run to completion.  This will be called whether
	 * the animator is stopped prematurely or ends naturally.
	 */
	protected abstract void finished();

	public void setBusyListener(BusyListener listener) {
		this.busyListener = listener;
	}

	@Override
	public boolean canShortcut() {
		return true;
	}

	@Override
	public void shortcut() {
		trace("shortcut(): " + this);
		isShortcut = true;
		stop();
	}

	@Override
	public void execute(GraphJobListener listener) {
		this.finishedListener = listener;
		start();
	}

	@Override
	public boolean isFinished() {
		return isFinished;
	}

	@Override
	public void dispose() {
		trace("dispose(): " + this);
		stop();
	}

	protected void trace(String message) {
		log.trace(message + " " + getClass().getSimpleName() + " (" +
			System.identityHashCode(this) + ")\t");
	}

	void start() {
		trace("start() - " + getClass().getSimpleName());

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
			});
		}

		animator.addTarget(new TimingTargetAdapter() {
			@Override
			public void end() {
				callFinish();
			}
		});

		animator.start();
	}

	private void callFinish() {
		trace("callFinish()");
		if (isFinished) {
			trace("\talready finished");
			return; // already called 
		}

		try {
			finished();
		}
		catch (Throwable t) {
			Msg.error(this, "Unexpected error in AbstractAnimator: ", t);
		}

		isFinished = true;

		// a null listener implies we were shortcut before we were started
		trace("\tmaybe notify finished...");
		if (finishedListener != null) {
			trace("\tlistener is not null--calling");
			finishedListener.jobFinished(this);
		}

		if (busyListener != null) {
			busyListener.setBusy(false);
		}
	}

	protected void stop() {
		trace("stop()");

		if (animator == null) {
			callFinish();
			return;
		}

		animator.stop();
	}

	@Override
	public String toString() {
		return getClass().getSimpleName();
	}
}
