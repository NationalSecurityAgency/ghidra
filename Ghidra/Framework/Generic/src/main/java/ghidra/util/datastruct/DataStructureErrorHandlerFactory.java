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
package ghidra.util.datastruct;

import ghidra.util.Msg;

/**
 * A class data structures can use to delegate error handling responsibilities to system-level
 * decision making.  This allows for specialized error handling in testing mode.
 */
public class DataStructureErrorHandlerFactory {

	// This field can be changed by the testing framework
	static ListenerErrorHandlerFactory listenerFactory = new ListenerErrorHandlerFactory() {
		@Override
		public ListenerErrorHandler createErrorHandler() {
			return new DefaultListenerErrorHandler();
		}
	};

	/**
	 * Creates a {@link ListenerErrorHandler}
	 * @return the error handler
	 */
	public static ListenerErrorHandler createListenerErrorHandler() {
		return listenerFactory.createErrorHandler();
	}

	private static class DefaultListenerErrorHandler implements ListenerErrorHandler {
		@Override
		public void handleError(Object listener, Throwable t) {
			Msg.error(listener, "Listener " + listener + " caused unexpected exception", t);
		}
	}
}
