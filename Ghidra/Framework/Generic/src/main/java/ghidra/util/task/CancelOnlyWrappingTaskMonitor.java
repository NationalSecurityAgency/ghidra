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
package ghidra.util.task;

/**
 * A monitor that is designed for sub-tasks, where the outer task handles reporting messages and
 * progress.  This class is really just for checking cancelled.
 * 
 * <P>This class wants the following methods related to cancelling to work normally:
 * <UL>
 *  <LI>isCancelled()</LI>
 *	<LI>checkCanceled()</LI>
 *	<LI>cancel()</LI>
 *	<LI>addCancelledListener(CancelledListener)</LI>
 *	<LI>removeCancelledListener(CancelledListener)</LI>
 *	<LI>addIssueListener(IssueListener)</LI>
 *	<LI>removeIssueListener(IssueListener)</LI>
 *	<LI>isCancelEnabled()</LI>
 *	</UL>		
 *
 *	<P>The rest of TaskMonitor should be stubbed out.  This means that if any methods are 
 *	added to the TaskMonitor interface, and subsequently implemented in this class's parent,
 *	then this class needs to override them.
 */
public class CancelOnlyWrappingTaskMonitor extends WrappingTaskMonitor {

	public CancelOnlyWrappingTaskMonitor(TaskMonitor delegate) {
		super(delegate);
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		// ignore
	}

	@Override
	public void setMessage(String message) {
		// ignore
	}

	@Override
	public void setProgress(long value) {
		// ignore
	}

	@Override
	public void initialize(long max) {
		// ignore
	}

	@Override
	public void setMaximum(long max) {
		// ignore
	}

	@Override
	public long getMaximum() {
		return 0;
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		// ignore
	}

	@Override
	public void incrementProgress(long incrementAmount) {
		// ignore
	}

	@Override
	public long getProgress() {
		return 0;
	}

	@Override
	public void setCancelEnabled(boolean enable) {
		// ignore
	}

	@Override
	public void clearCanceled() {
		// ignore
	}
}
