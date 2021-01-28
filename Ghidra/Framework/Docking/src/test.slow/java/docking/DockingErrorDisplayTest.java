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

import static org.junit.Assert.*;

import java.awt.Window;
import java.util.Collections;

import org.junit.Test;

import docking.test.AbstractDockingTest;
import ghidra.util.DefaultErrorLogger;
import ghidra.util.exception.MultipleCauses;

public class DockingErrorDisplayTest extends AbstractDockingTest {

	private static final String TEST_TITLE = "Test Title";

	@Test
	public void testDefaultErrorDisplay_SingleException() {
		DockingErrorDisplay display = new DockingErrorDisplay();
		DefaultErrorLogger logger = new DefaultErrorLogger();
		Exception exception = new Exception("My test exception");
		reportException(display, logger, exception);

		assertErrLogDialog();
	}

	@Test
	public void testDefaultErrorDisplay_NestedException() {
		DockingErrorDisplay display = new DockingErrorDisplay();
		DefaultErrorLogger logger = new DefaultErrorLogger();
		Exception nestedException = new Exception("My nested test exception");
		Exception exception = new Exception("My test exception", nestedException);
		reportException(display, logger, exception);

		assertErrLogDialog();
	}

	@Test
	public void testDefaultErrorDisplay_MultipleAsynchronousExceptions() {

		DockingErrorDisplay display = new DockingErrorDisplay();
		DefaultErrorLogger logger = new DefaultErrorLogger();
		Exception exception = new Exception("My test exception");
		reportException(display, logger, exception);

		ErrLogDialog dialog = getErrLogDialog();

		assertExceptionCount(dialog, 1);

		reportException(display, logger, new NullPointerException("It is null!"));
		assertExceptionCount(dialog, 2);

		reportException(display, logger, new NullPointerException("It is null!"));
		assertExceptionCount(dialog, 3);

		assertEquals("Test Title (3 Errors)", dialog.getTitle());

		close(dialog);
	}

	@Test
	public void testMultipleCausesErrorDisplay() {
		DockingErrorDisplay display = new DockingErrorDisplay();
		DefaultErrorLogger logger = new DefaultErrorLogger();

		Throwable firstCause = new Exception("My test exception - first cause");
		MultipleCauses exception = new MultipleCauses(Collections.singletonList(firstCause));
		reportException(display, logger, exception);

		ErrLogExpandableDialog dialog = assertErrLogExpandableDialog();
		assertExceptionCount(dialog, 1);

		reportException(display, logger, new NullPointerException("It is null!"));
		assertExceptionCount(dialog, 2);

		close(dialog);
	}

	private void assertExceptionCount(AbstractErrDialog errDialog, int n) {

		int actual = errDialog.getExceptionCount();
		assertEquals(n, actual);
	}

	private ErrLogExpandableDialog assertErrLogExpandableDialog() {
		Window w = waitForWindow(TEST_TITLE);

		ErrLogExpandableDialog errDialog =
			getDialogComponentProvider(w, ErrLogExpandableDialog.class);
		assertNotNull(errDialog);
		return errDialog;
	}

	private void assertErrLogDialog() {
		Window w = waitForWindow(TEST_TITLE);
		assertNotNull(w);

		ErrLogDialog errDialog = getDialogComponentProvider(w, ErrLogDialog.class);
		assertNotNull(errDialog);
		close(errDialog);
	}

	private ErrLogDialog getErrLogDialog() {
		Window w = waitForWindow(TEST_TITLE);
		assertNotNull(w);

		ErrLogDialog errDialog = getDialogComponentProvider(w, ErrLogDialog.class);
		assertNotNull(errDialog);
		return errDialog;
	}

	private void reportException(final DockingErrorDisplay display, final DefaultErrorLogger logger,
			final Throwable throwable) {
		runSwing(new Runnable() {
			@Override
			public void run() {
				logger.error(this, ">>>>>>>>>>>>>>>> Expected Exception");
				display.displayErrorMessage(logger, this, null, TEST_TITLE, "Test Message",
					throwable);
				logger.error(this, "<<<<<<<<<<<<<<<< End Expected Exception");
			}
		}, false);
		waitForSwing();
	}

}
