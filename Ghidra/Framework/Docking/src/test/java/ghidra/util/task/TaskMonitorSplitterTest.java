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

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import docking.test.AbstractDockingTest;
import generic.test.AbstractGenericTest;

public class TaskMonitorSplitterTest extends AbstractDockingTest {
	TaskMonitor baseMonitor;

	public TaskMonitorSplitterTest() {
		super();
		baseMonitor = new TaskMonitorComponent();
	}

	@Test
	public void testBasicUse() {
		TaskMonitor[] monitors = TaskMonitorSplitter.splitTaskMonitor(baseMonitor, 4);

		monitors[0].initialize(100);
		monitors[0].setProgress(1);
		assertEquals(1, monitors[0].getProgress());
		assertEquals(TaskMonitorSplitter.MONITOR_SIZE / 400, baseMonitor.getProgress());

		monitors[0].incrementProgress(1);
		assertEquals(2 * TaskMonitorSplitter.MONITOR_SIZE / 400, baseMonitor.getProgress());

		monitors[0].setProgress(10);
		assertEquals(10 * TaskMonitorSplitter.MONITOR_SIZE / 400, baseMonitor.getProgress());

	}

	@Test
	public void testMaxSettings() {
		TaskMonitor[] monitors = TaskMonitorSplitter.splitTaskMonitor(baseMonitor, 4);

		monitors[0].initialize(100);
		monitors[0].setProgress(50);
		assertEquals(50 * TaskMonitorSplitter.MONITOR_SIZE / 400, baseMonitor.getProgress());

		monitors[0].setMaximum(25);
		assertEquals(25, monitors[0].getMaximum());
		assertEquals(TaskMonitorSplitter.MONITOR_SIZE / 4, baseMonitor.getProgress());

		monitors[0].setMaximum(100);
		assertEquals(25 * TaskMonitorSplitter.MONITOR_SIZE / 400, baseMonitor.getProgress());

	}

}
