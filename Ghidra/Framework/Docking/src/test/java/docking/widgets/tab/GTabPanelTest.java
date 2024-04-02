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
import java.util.function.Predicate;

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
	public void testFirstTabIsSelectedByDefault() {
		assertEquals("One", getSelectedValue());
	}

	@Test
	public void testAddValue() {
		assertEquals(3, getTabCount());
		assertEquals("One", getSelectedValue());
		addValue("Four");
		assertEquals(4, getTabCount());
		assertEquals("One", getSelectedValue());
		assertEquals("Four", getValue(3));
	}

	@Test
	public void testSwitchSelected() {
		setSelectedValue("Two");
		assertEquals("Two", getSelectedValue());
	}

	@Test
	public void testSwitchToInvalidValue() {
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
		assertEquals(3, getTabCount());
		assertEquals("One", getSelectedValue());
		removeTab("One");
		assertEquals(2, getTabCount());
		assertEquals("Two", getSelectedValue());
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
		AtomicReference<String> removedValue = new AtomicReference<String>();
		Consumer<String> c = s -> removedValue.set(s);
		runSwing(() -> gTabPanel.setRemovedTabConsumer(c));
		runSwing(() -> gTabPanel.closeTab("Two"));
		assertEquals("Two", removedValue.get());
	}

	@Test
	public void testSetRemoveTabPredicateAcceptsRemove() {
		AtomicReference<String> removePredicateCallValue = new AtomicReference<String>();
		Predicate<String> p = s -> {
			removePredicateCallValue.set(s);
			return true;
		};
		runSwing(() -> gTabPanel.setRemoveTabActionPredicate(p));
		runSwing(() -> gTabPanel.closeTab("Two"));
		assertEquals("Two", removePredicateCallValue.get());
		assertEquals(2, getTabCount());
	}

	@Test
	public void testSetRemoveTabPredicateRejectsRemove() {
		AtomicReference<String> removePredicateCallValue = new AtomicReference<String>();
		Predicate<String> p = s -> {
			removePredicateCallValue.set(s);
			return false;
		};
		runSwing(() -> gTabPanel.setRemoveTabActionPredicate(p));
		runSwing(() -> gTabPanel.closeTab("Two"));
		assertEquals("Two", removePredicateCallValue.get());
		assertEquals(3, getTabCount());
	}

	@Test
	public void testHighlightNext() {
		assertNull(gTabPanel.getHighlightedTabValue());
		runSwing(() -> gTabPanel.highlightNextTab(true));
		assertEquals("Two", gTabPanel.getHighlightedTabValue());
		runSwing(() -> gTabPanel.highlightNextTab(true));
		assertEquals("Three Three Three", gTabPanel.getHighlightedTabValue());
		runSwing(() -> gTabPanel.highlightNextTab(false));
		assertEquals("Two", gTabPanel.getHighlightedTabValue());
		runSwing(() -> gTabPanel.highlightNextTab(false));
		assertNull(gTabPanel.getHighlightedTabValue());
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

	private void removeTab(String value) {
		runSwing(() -> gTabPanel.removeTab(value));
	}

	private int getTabCount() {
		return runSwing(() -> gTabPanel.getTabCount());
	}

	private String getSelectedValue() {
		return runSwing(() -> gTabPanel.getSelectedTabValue());
	}

	private String getValue(int i) {
		return runSwing(() -> gTabPanel.getTabValues().get(i));
	}
}
