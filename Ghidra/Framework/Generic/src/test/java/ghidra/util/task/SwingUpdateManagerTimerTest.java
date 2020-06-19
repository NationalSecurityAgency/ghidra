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

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class SwingUpdateManagerTimerTest extends AbstractGenericTest {
	private static final int MIN_DELAY = 100;
	private static final int MAX_DELAY = 10000;
	private volatile int runnableCalled;
	private SwingUpdateManager manager;

	@Before
	public void setUp() throws Exception {
		manager = createUpdateManager(MIN_DELAY, MAX_DELAY);

		// must turn this on to get the expected results, as in headless mode the update manager
		// will run it's Swing work immediately on the test thread, which is not true to the
		// default behavior
		System.setProperty(SystemUtilities.HEADLESS_PROPERTY, Boolean.FALSE.toString());
	}

	@Test
	public void testNotFiringTooOften() throws InterruptedException {
		Thread t = new Thread(() -> {
			for (int i = 0; i < 50; i++) {
				manager.update();
				manager.update();
				manager.update();
				manager.update();
				sleep(10);
			}
		});
		t.start();
		t.join();
		waitForManager();
		assertEquals(2, runnableCalled);
	}

//==================================================================================================
// Private Methods
//==================================================================================================
	private void waitForManager() {

		// let all swing updates finish, which may trigger the update manager
		waitForSwing();

		while (manager.isBusy()) {
			sleep(DEFAULT_WAIT_DELAY);
		}

		// let any resulting swing events finish
		waitForSwing();
	}

	private SwingUpdateManager createUpdateManager(int min, int max) {
		return new SwingUpdateManager(min, max, "bob", new Runnable() {

			@Override
			public void run() {
				runnableCalled++;
				Msg.debug(this, "run() called - count: " + runnableCalled);
			}
		});
	}
}
