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

import generic.test.ConcurrentTestExceptionHandler;

/**
 * A utility that allows tests to set the error handling behavior for all data structures that
 * want flexible error handling.  This class, in this package, allows us to override the factory
 * that is used to create the error handlers for framework listener data structures.  The standard
 * behavior is to report errors to the the application log.  Some clients wish to change this
 * behavior in testing mode so that any errors will fail tests.  Without overriding this behavior,
 * unexpected errors during listener notification may be lost in the noise of the application log.
 * <p>
 * The {@link ConcurrentTestExceptionHandler} is the mechanism used to report errors.  That class
 * allows the testing framework to synchronize error reporting, including to fail tests when errors
 * are encountered, in any thread.  Tests can disable this failure behavior by calling
 * {@link ConcurrentTestExceptionHandler#disable()}.  Doing so allows tests to prevent test failure
 * when encountering expected errors.
 */
public class TestDataStructureErrorHandlerInstaller {

	public static void installConcurrentExceptionErrorHandler() {

		DataStructureErrorHandlerFactory.listenerFactory = new ListenerErrorHandlerFactory() {
			@Override
			public ListenerErrorHandler createErrorHandler() {
				return new ConcurrentErrorHandler();
			}
		};
	}

	private static class ConcurrentErrorHandler implements ListenerErrorHandler {
		@Override
		public void handleError(Object listener, Throwable t) {
			ConcurrentTestExceptionHandler.handle(Thread.currentThread(), t);
		}
	}
}
