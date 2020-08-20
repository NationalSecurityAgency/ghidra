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
package docking;

import utility.function.Callback;

/**
 * A dialog that is meant to be extended for showing exceptions
 */
abstract class AbstractErrDialog extends DialogComponentProvider {

	// at some point, there are too many exceptions to show
	protected static final int MAX_EXCEPTIONS = 100;
	protected static final String TITLE_TEXT = "Multiple Errors";

	private Callback closedCallback = Callback.dummy();

	protected AbstractErrDialog(String title) {
		super(title, true, false, true, false);
	}

	@Override
	protected final void dialogClosed() {
		closedCallback.call();
	}

	abstract void addException(String message, Throwable t);

	abstract int getExceptionCount();

	void setClosedCallback(Callback callback) {
		closedCallback = Callback.dummyIfNull(callback);
	}
}
