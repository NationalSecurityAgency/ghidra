/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.task;

import ghidra.util.exception.AssertException;

/**
 * Used by the GTaskManager to efficiently manage multiple GTaskListeners.  
 * <P>
 * When an GTaskManager has multiple listeners, instead of having a list of listeners, listeners
 * are chained together using MulticastTaskListeners. It avoids the creation of
 * an iterator every time a listener method needs to be called.
 * <P>
 * For example, the GTaskManager has a single TaskListener variable that it notifies when its state
 * changes.  If someone adds a listener, and the current listener is null, then it becomes the 
 * listener.  If it already has a listener, it will create a new MulticaseTaskListener taking in the
 * old listener and the new listener.  When a TaskListener method is called, it simply calls the same
 * method on those two listeners.
 * 
 */
class MulticastTaskListener implements GTaskListener {
	private GTaskListener a;
	private GTaskListener b;

	public MulticastTaskListener(GTaskListener a, GTaskListener b) {
		this.a = a;
		this.b = b;
	}

	@Override
	public void taskStarted(GScheduledTask task) {
		a.taskStarted(task);
		b.taskStarted(task);
	}

	@Override
	public void taskCompleted(GScheduledTask task, GTaskResult result) {
		a.taskCompleted(task, result);
		b.taskCompleted(task, result);
	}

	@Override
	public void taskGroupScheduled(GTaskGroup group) {
		a.taskGroupScheduled(group);
		b.taskGroupScheduled(group);
	}

	@Override
	public void taskScheduled(GScheduledTask scheduledTask) {
		a.taskScheduled(scheduledTask);
		b.taskScheduled(scheduledTask);
	}

	@Override
	public void taskGroupStarted(GTaskGroup taskGroup) {
		a.taskGroupStarted(taskGroup);
		b.taskGroupStarted(taskGroup);
	}

	public GTaskListener removeListener(GTaskListener listener) {
		if (a == listener) {
			return b;
		}
		else if (b == listener) {
			return a;
		}
		if (a instanceof MulticastTaskListener) {
			MulticastTaskListener ma = (MulticastTaskListener) a;
			a = ma.removeListener(listener);
		}
		if (b instanceof MulticastTaskListener) {
			MulticastTaskListener mb = (MulticastTaskListener) b;
			b = mb.removeListener(listener);
		}
		return this;
	}

	@Override
	public void initialize() {
		// Special case: initialize() should only be called once when a new listener is added.  So
		// initialize is called on the new listener before it is added to a MulticastTaskListener, 
		// therefore, this should never be called on a MulticastTaskListener.
		throw new AssertException("Initialize should not be called here.");
	}

	@Override
	public void taskGroupCompleted(GTaskGroup taskGroup) {
		a.taskGroupCompleted(taskGroup);
		b.taskGroupCompleted(taskGroup);
	}

	@Override
	public void suspendedStateChanged(boolean suspended) {
		a.suspendedStateChanged(suspended);
		b.suspendedStateChanged(suspended);
	}

}
