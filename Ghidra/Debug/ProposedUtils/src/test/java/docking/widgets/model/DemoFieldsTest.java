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
package docking.widgets.model;

import static org.junit.Assume.assumeFalse;

import java.awt.BorderLayout;

import javax.swing.JButton;
import javax.swing.JFrame;

import org.junit.Before;
import org.junit.Test;

import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class DemoFieldsTest extends AbstractGhidraHeadedIntegrationTest {
	@Before
	public void checkNotBatch() {
		assumeFalse(SystemUtilities.isInTestingBatchMode());
	}

	@Test
	public void testDemoGLifespanField() throws InterruptedException {
		GLifespanField spanField = new GLifespanField();

		JFrame frame = new JFrame("Demo GLifespanField");
		frame.setBounds(40, 40, 400, 90);
		frame.setLayout(new BorderLayout());
		frame.add(spanField);
		frame.setVisible(true);

		JButton button = new JButton("Print");
		button.addActionListener(evt -> {
			Msg.info(this, "Lifespan: " + spanField.getLifespan());
		});
		frame.add(button, BorderLayout.SOUTH);

		Thread.sleep(1000000);
	}

	@Test
	public void testDemoGAddressRangeField() throws InterruptedException {
		GAddressRangeField rangeField = new GAddressRangeField();
		rangeField.setAddressFactory(getSLEIGH_X86_64_LANGUAGE().getAddressFactory());

		JFrame frame = new JFrame("Demo GAddressRangeField");
		frame.setBounds(40, 40, 400, 90);
		frame.setLayout(new BorderLayout());
		frame.add(rangeField);
		frame.setVisible(true);

		JButton button = new JButton("Print");
		button.addActionListener(evt -> {
			Msg.info(this, "Range: " + rangeField.getRange());
		});
		frame.add(button, BorderLayout.SOUTH);

		Thread.sleep(1000000);
	}
}
