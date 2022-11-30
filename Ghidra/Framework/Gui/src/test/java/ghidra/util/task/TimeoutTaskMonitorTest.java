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

import static org.junit.Assert.*;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.TimeoutException;

public class TimeoutTaskMonitorTest extends AbstractGenericTest {

	@Test
	public void testTimeout() {
		int timeout = 100;
		TimeoutTaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(100, TimeUnit.MILLISECONDS);
		assertFalse(monitor.didTimeout());

		sleep(timeout * 2);

		try {
			monitor.checkCanceled();
			fail();
		}
		catch (TimeoutException e) {
			// expected
		}
		catch (CancelledException e) {
			fail("Should have a TimeoutException instead of a CancelledException");
		}

		assertTrue(monitor.didTimeout());
	}

	@Test
	public void testTimeout_Callback() {
		int timeout = 100;
		TimeoutTaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(100, TimeUnit.MILLISECONDS);

		AtomicBoolean called = new AtomicBoolean();
		monitor.setTimeoutListener(() -> called.set(true));

		sleep(timeout * 2);

		assertTrue(called.get());
	}
}
