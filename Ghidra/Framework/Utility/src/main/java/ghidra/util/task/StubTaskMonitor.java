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

import ghidra.util.exception.CancelledException;

class StubTaskMonitor implements TaskMonitor {

	@Override
	public boolean isCancelled() {
		return false;
	}

	@Override
	public void setShowProgressValue(boolean showProgressValue) {
		// stub

	}

	@Override
	public void setMessage(String message) {
		// stub
	}

	@Override
	public String getMessage() {
		return null;
	}

	@Override
	public void setProgress(long value) {
		// stub

	}

	@Override
	public void initialize(long max) {
		// stub

	}

	@Override
	public void setMaximum(long max) {
		// stub

	}

	@Override
	public long getMaximum() {
		return 0;
	}

	@Override
	public void setIndeterminate(boolean indeterminate) {
		// stub
	}

	@Override
	public boolean isIndeterminate() {
		return false;
	}

	@Override
	public void checkCanceled() throws CancelledException {
		// stub

	}

	@Override
	public void incrementProgress(long incrementAmount) {
		// stub

	}

	@Override
	public long getProgress() {
		// stub
		return 0;
	}

	@Override
	public void cancel() {
		// stub

	}

	@Override
	public void addCancelledListener(CancelledListener listener) {
		// stub

	}

	@Override
	public void removeCancelledListener(CancelledListener listener) {
		// stub

	}

	@Override
	public void setCancelEnabled(boolean enable) {
		// stub

	}

	@Override
	public boolean isCancelEnabled() {
		// stub
		return false;
	}

	@Override
	public void clearCanceled() {
		// stub

	}
}
