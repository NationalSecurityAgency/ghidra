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
package ghidra.util.timer;

import static org.junit.Assert.*;

import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.util.Msg;
import ghidra.util.timer.Watchdog;

public class WatchdogTest extends AbstractGTest {

	@Test(timeout = 20000)
	public void test() {
		long watchdogTimeoutMS = 10;

		// watchdog could take N*2 to trigger
		long watchdogMaxIntrMS = watchdogTimeoutMS * 3;
		AtomicBoolean inerruptedFlag = new AtomicBoolean();

		Thread testThread = Thread.currentThread();
		try (Watchdog watchDog = new Watchdog(watchdogTimeoutMS, () -> {
			Msg.trace(this, "" + System.currentTimeMillis() + ": Interrupting the test thread...");
			inerruptedFlag.set(true);
			testThread.interrupt();
		})) {

			for (int i = 0; i < 10; i++) {
				inerruptedFlag.set(false);
				watchDog.arm();
				long start = System.currentTimeMillis();
				try {
					Thread.sleep(DEFAULT_WAIT_TIMEOUT);
					fail(System.currentTimeMillis() + ": Watchdog did not fire");
				}
				catch (InterruptedException e) {
					assertTrue("" + System.currentTimeMillis() +
						": Sleep was interrupted, but not by watchdog", inerruptedFlag.get());
					long elapsed = System.currentTimeMillis() - start;
					Msg.trace(this, System.currentTimeMillis() + ": Watchdog fired in: " + elapsed +
						"ms, max target is: " + watchdogMaxIntrMS + "ms");
				}
			}
		}

	}

}
