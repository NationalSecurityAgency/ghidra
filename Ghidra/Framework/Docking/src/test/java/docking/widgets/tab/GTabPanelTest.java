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
package docking.widgets.tab;

import static org.junit.Assert.*;

import java.awt.BorderLayout;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import javax.swing.*;

import org.junit.*;

import docking.test.AbstractDockingTest;

public class GTabPanelTest extends AbstractDockingTest {

	private GTabPanel<String> gTabPanel;
	private JFrame parentFrame;

	@Before
	public void setUp() throws Exception {

		runSwing(() -> {
			gTabPanel = new GTabPanel<String>("Test");
			gTabPanel.addTab("One");
			gTabPanel.addTab("Two");
			gTabPanel.addTab("Three Three Three");

			JPanel panel = new JPanel();
			panel.setLayout(new BorderLayout());
			panel.add(gTabPanel, BorderLayout.NORTH);

			JTextArea textArea = new JTextArea(20, 100);
			panel.add(textArea, BorderLayout.CENTER);

			parentFrame = new JFrame(GTabPanel.class.getName());
			parentFrame.getContentPane().add(panel);
			parentFrame.pack();
			parentFrame.setVisible(true);
			parentFrame.setLocation(1000, 200);
		});
	}

	@After
	public void tearDown() {
		parentFrame.setVisible(false);
	}

	@Test
	public void testNoTabIsSelectedByDefault() {
		assertEquals(null, getSelectedValue());
	}

	@Test
	public void testSettingNoTabSelected() {

		AtomicReference<String> selectedValue = new AtomicReference<String>();
		Consumer<String> c = s -> selectedValue.set(s);
		runSwing(() -> gTabPanel.setSelectedTabConsumer(c));
		setSelectedValue("One");
		assertEquals("One", selectedValue.get());
		setSelectedValue(null);
		assertEquals(null, selectedValue.get());
	}

	@Test
	public void testAddValue() {
		assertEquals(3, getTabCount());
		assertEquals(null, getSelectedValue());
		addValue("Four");
		assertEquals(4, getTabCount());
		assertEquals(null, getSelectedValue());
		assertEquals("Four", getValue(3));
	}

	@Test
	public void testSwitchSelected() {
		setSelectedValue("Two");
		assertEquals("Two", getSelectedValue());
	}

	@Test
	public void testSwitchToInvalidValue() {
		setSelectedValue("One");
		try {
			gTabPanel.selectTab("Four");
			fail("expected exception");
		}
		catch (IllegalArgumentException e) {
			//expected
		}
		assertEquals("One", getSelectedValue());

	}

	@Test
	public void testCloseSelected() {
		setSelectedValue("One");
		assertEquals(3, getTabCount());
		assertEquals("One", getSelectedValue());
		removeTab("One");
		assertEquals(2, getTabCount());
		assertNull(getSelectedValue());
	}

	@Test
	public void testSelectedTabIsVisible() {
		addValue("asdfasfasfdasfasfasfasfasfasfasfasfasfasfasfasfsaasasfassafsasf");
		addValue("ABCDEFGHIJK");
		assertFalse(isVisibleTab("ABCDEFGHIJK"));
		setSelectedValue("ABCDEFGHIJK");
		assertTrue(isVisibleTab("ABCDEFGHIJK"));
		setSelectedValue("One");
		assertFalse(isVisibleTab("ABCDEFGHIJK"));
	}

	@Test
	public void testGetHiddenTabs() {
		List<String> hiddenTabs = getHiddenTabs();
		assertTrue(hiddenTabs.isEmpty());
		addValue("asdfasfasfdasfasfasfasfasfasfasfasfasfasfasfasfsaasasfassafsasf");
		addValue("ABCDEFGHIJK");
		hiddenTabs = getHiddenTabs();
		assertEquals(2, hiddenTabs.size());
		assertTrue(hiddenTabs.contains("ABCDEFGHIJK"));
	}

	@Test
	public void testHighlightTab() {
		assertNull(gTabPanel.getHighlightedTabValue());
		gTabPanel.highlightTab("Two");
		assertEquals("Two", gTabPanel.getHighlightedTabValue());
	}

	@Test
	public void testSelectedConsumer() {
		AtomicReference<String> selectedValue = new AtomicReference<String>();
		Consumer<String> c = s -> selectedValue.set(s);
		runSwing(() -> gTabPanel.setSelectedTabConsumer(c));
		setSelectedValue("Two");
		assertEquals("Two", selectedValue.get());
		setSelectedValue("One");
		assertEquals("One", selectedValue.get());
	}

	@Test
	public void testRemovedConsumer() {
		AtomicReference<String> closedValue = new AtomicReference<String>();
		Consumer<String> c = s -> closedValue.set(s);
		runSwing(() -> gTabPanel.setCloseTabConsumer(c));
		runSwing(() -> gTabPanel.closeTab("Two"));
		assertEquals("Two", closedValue.get());
	}

	@Test
	public void testSetRemoveTabConsumer() {
		AtomicReference<String> closedValueReference = new AtomicReference<String>();
		Consumer<String> c = s -> {
			closedValueReference.set(s);
			gTabPanel.removeTab(s);
		};
		runSwing(() -> gTabPanel.setCloseTabConsumer(c));
		runSwing(() -> gTabPanel.closeTab("Two"));
		assertEquals("Two", closedValueReference.get());
		assertEquals(2, getTabCount());
	}

	@Test
	public void testHighlightNext() {
		assertNull(getHighlightedValue());
		highlightNextTab(true);
		assertEquals("One", getHighlightedValue());
		highlightNextTab(true);
		assertEquals("Two", getHighlightedValue());
		highlightNextTab(false);
		assertEquals("One", getHighlightedValue());
		highlightNextTab(false);
		assertEquals("Three Three Three", getHighlightedValue());
		setSelectedValue("One");
		highlightNextTab(true);
		assertEquals("Two", getHighlightedValue());
	}

	@Test
	public void testGetAccessibleNameNoTabs() {
		removeTab("One");
		removeTab("Two");
		removeTab("Three Three Three");
		assertEquals("Test Tab Panel: No Tabs", gTabPanel.getAccessibleName());
	}

	@Test
	public void testGetAccessibleNameNoTabSelected() {
		setSelectedValue(null);
		assertEquals("Test Tab Panel: No Selected Tab", gTabPanel.getAccessibleName());
	}

	@Test
	public void testGetAccessiblNameTabSelected() {
		setSelectedValue("Two");
		assertEquals("Test Tab Panel: Two selected", gTabPanel.getAccessibleName());
	}

	@Test
	public void testGetAccessiblNameNoTabSelectedAndTabHighighted() {
		setSelectedValue(null);
		highlightNextTab(true);
		assertEquals("Test Tab Panel: No Selected Tab: One highlighted",
			gTabPanel.getAccessibleName());
	}

	@Test
	public void testGetAccessiblNameTabSelectedAndTabHighighted() {
		setSelectedValue("One");
		highlightNextTab(true);
		assertEquals("Test Tab Panel: One selected: Two highlighted",
			gTabPanel.getAccessibleName());
	}

	private List<String> getHiddenTabs() {
		return runSwing(() -> gTabPanel.getHiddenTabs());
	}

	private boolean isVisibleTab(String value) {
		return runSwing(() -> gTabPanel.isVisibleTab(value));
	}

	private void addValue(String value) {
		runSwing(() -> gTabPanel.addTab(value));
	}

	private void setSelectedValue(String value) {
		runSwing(() -> gTabPanel.selectTab(value));
	}

	private void highlightNextTab(boolean b) {
		runSwing(() -> gTabPanel.highlightNextPreviousTab(b));
	}

	private void removeTab(String value) {
		runSwing(() -> gTabPanel.removeTab(value));
	}

	private int getTabCount() {
		return runSwing(() -> gTabPanel.getTabCount());
	}

	private String getSelectedValue() {
		return runSwing(() -> gTabPanel.getSelectedTabValue());
	}

	private String getHighlightedValue() {
		return runSwing(() -> gTabPanel.getHighlightedTabValue());
	}

	private String getValue(int i) {
		return runSwing(() -> gTabPanel.getTabValues().get(i));
	}
}
