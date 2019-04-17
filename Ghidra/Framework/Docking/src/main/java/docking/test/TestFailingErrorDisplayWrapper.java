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
package docking.test;

import java.awt.Component;

import generic.test.ConcurrentTestExceptionHandler;
import ghidra.util.ErrorDisplay;
import ghidra.util.ErrorLogger;

/**
 * An error display wrapper that allows us to fail tests when errors are encountered.  This is 
 * a way for us to fail for exceptions that come from client code, but are handled by the 
 * error display service, while running tests.
 */
public class TestFailingErrorDisplayWrapper implements ErrorDisplay {

	private ErrorDisplay delegate;

	public void setErrorDisplayDelegate(ErrorDisplay delegate) {
		this.delegate = delegate;
	}

	@Override
	public void displayInfoMessage(ErrorLogger errorLogger, Object originator, Component parent,
			String title, Object message) {
		delegate.displayInfoMessage(errorLogger, originator, parent, title, message);
	}

	@Override
	public void displayErrorMessage(ErrorLogger errorLogger, Object originator, Component parent,
			String title, Object message, Throwable throwable) {

		if (!ConcurrentTestExceptionHandler.isEnabled()) {
			// cheat: we don't want stack traces being printed to the log when we errors are 
			//        disabled
			throwable = null;
		}

		delegate.displayErrorMessage(errorLogger, originator, parent, title, message, throwable);

		// This allows us to track from where clients are calling showError()
//		if (throwable == null) {
//			throwable = ExceptionUtilities.createThrowableWithStackOlderThan(Msg.class);
//		}

		if (throwable != null) {
			ConcurrentTestExceptionHandler.handle(Thread.currentThread(), throwable);
		}
	}

	@Override
	public void displayWarningMessage(ErrorLogger errorLogger, Object originator, Component parent,
			String title, Object message, Throwable throwable) {

		if (!ConcurrentTestExceptionHandler.isEnabled()) {
			// cheat: we don't want stack traces being printed to the log when we errors are 
			//        disabled
			throwable = null;
		}

		delegate.displayWarningMessage(errorLogger, originator, parent, title, message, throwable);

		if (throwable != null) {
			// For now, only report exceptions; warning messages don't' seem important enough
			// to fail a test.  We can always change this.  
			ConcurrentTestExceptionHandler.handle(Thread.currentThread(), throwable);
		}
	}
}
