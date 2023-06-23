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

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.exception.CancelledException;

public class UnknownProgressWrappingTaskMonitorTest extends AbstractGenericTest {

	@Test
	public void testUPWTM_checkCanceled_1L_vs_2L() {
		TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
		monitor.cancel();
		UnknownProgressWrappingTaskMonitor upwtm =
			new UnknownProgressWrappingTaskMonitor(monitor, 100);
		try {
			upwtm.checkCanceled();
			fail();
		}
		catch (CancelledException e) {
			// good
		}

		try {
			upwtm.checkCancelled();
			fail();
		}
		catch (CancelledException e) {
			// good
		}

	}

}
