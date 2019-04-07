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
package ghidra.framework.task;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import ghidra.framework.task.gui.GProgressBar;
import ghidra.util.task.CancelledListener;

public class GProgressBarTest extends AbstractDockingTest {

	protected boolean cancelled;
	private CancelledListener cancelledListener;
	private GProgressBar progressBar;

	@Before
	public void setUp() throws Exception {

		cancelledListener = new CancelledListener() {

			@Override
			public void cancelled() {
				cancelled = true;
			}
		};
		progressBar = new GProgressBar(cancelledListener, true, true, true, 10.0f);
	}

	@Test
    public void testBasicProgress() {
		progressBar.initialize(100);
		assertEquals(0, progressBar.getProgress());
		assertEquals(100, progressBar.getMax());
		assertEquals(null, progressBar.getMessage());

		progressBar.setProgress(5);
		assertEquals(5, progressBar.getProgress());
		assertJProgressBar(5, 100);
	}

	@Test
    public void testLongValues() {
		progressBar.initialize(0x400000000L);
		progressBar.setProgress(10);
		assertEquals(10, progressBar.getProgress());
		assertEquals(0x400000000L, progressBar.getMax());
		assertEquals(null, progressBar.getMessage());
		assertJProgressBar(1, (int) (0x400000000L / 10));

	}

	@Test
    public void testMessage() {
		progressBar.initialize(100);
		progressBar.setMessage("Hey");
		assertEquals("Hey", progressBar.getMessage());
		assertLabel("Hey");
		progressBar.initialize(100);
		assertEquals(null, progressBar.getMessage());
		assertLabel("");

	}

	private void assertLabel(String string) {
		waitForTimer();
		JLabel label = (JLabel) getInstanceField("messageLabel", progressBar);
		assertEquals(string, getMessage(label));
	}

	@Test
    public void testCancel() {
		progressBar.initialize(100);
		progressBar.setProgress(50);
		assertTrue(!cancelled);
		progressBar.cancel();
		assertTrue(cancelled);
	}

	private void assertJProgressBar(int progress, int max) {
		waitForTimer();
		JProgressBar jProgressBar = (JProgressBar) getInstanceField("progressBar", progressBar);
		assertEquals(progress, getProgress(jProgressBar));
		assertEquals(max, getMaximum(jProgressBar));
	}

	private int getProgress(final JProgressBar jProgressBar) {
		final AtomicInteger result = new AtomicInteger();
		runSwing(new Runnable() {
			@Override
			public void run() {
				result.set(jProgressBar.getValue());
			}
		});
		return result.get();
	}

	private int getMaximum(final JProgressBar jProgressBar) {
		final AtomicInteger result = new AtomicInteger();
		runSwing(new Runnable() {
			@Override
			public void run() {
				result.set(jProgressBar.getMaximum());
			}
		});
		return result.get();
	}

	private String getMessage(final JLabel label) {
		final AtomicReference<String> result = new AtomicReference<String>();
		runSwing(new Runnable() {
			@Override
			public void run() {
				result.set(label.getText());
			}
		});
		return result.get();
	}

	private void waitForTimer() {
		Timer timer = (Timer) getInstanceField("updateTimer", progressBar);
		while (timer.isRunning()) {
			sleep(10);
		}
	}
}
