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
package docking.widgets.searchlist;

import static org.junit.Assert.*;

import java.awt.BorderLayout;
import java.awt.event.KeyEvent;
import java.util.List;

import javax.swing.*;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;

public class SearchListTest extends AbstractDockingTest {
	private SearchList<String> searchList;
	private DefaultSearchListModel<String> model;
	private JFrame parentFrame;
	private String lastChoiceValue;
	private String lastChoiceCategory;

	@Before
	public void setUp() throws Exception {
		model = createModel();
		searchList = new SearchList<>(model, (t, c) -> choiceMade(t, c));

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		panel.add(searchList, BorderLayout.CENTER);

		parentFrame = new JFrame(SearchList.class.getName());
		parentFrame.getContentPane().removeAll();
		parentFrame.getContentPane().add(panel);
		parentFrame.pack();
		parentFrame.setVisible(true);

	}

	@Test
	public void testFilterReducesNumberOfElements() {
		assertEquals(8, model.getSize());
		List<SearchListEntry<String>> allItems = model.getAllItems();
		List<SearchListEntry<String>> displayed = model.getDisplayedItems();
		assertEquals(allItems, displayed);

		setFilterText("d");
		assertEquals(2, model.getSize());
		List<SearchListEntry<String>> displayedItems = model.getDisplayedItems();
		assertEquals("date", displayedItems.get(0).value());
		assertEquals("dill", displayedItems.get(1).value());
	}

	@Test
	public void testCategoryNotConsideredInFilter() {
		assertEquals(8, model.getSize());

		setFilterText("f");
		assertEquals(0, model.getSize());

	}

	@Test
	public void testClearFilterRestores() {
		assertEquals(8, model.getSize());
		setFilterText("apple");
		assertEquals(1, model.getSize());
		setFilterText("");
		assertEquals(8, model.getSize());

	}

	@Test
	public void testSelect() {
		JTextField textField = searchList.getTextField();
		triggerActionKey(textField, 0, KeyEvent.VK_DOWN);

		assertNull(lastChoiceValue);
		assertNull(lastChoiceCategory);
		triggerEnter(textField);
		assertEquals("apple", lastChoiceValue);
		assertEquals("fruits", lastChoiceCategory);
		triggerActionKey(textField, 0, KeyEvent.VK_DOWN);
		triggerEnter(textField);
		assertEquals("banana", lastChoiceValue);
		assertEquals("fruits", lastChoiceCategory);
	}

	private DefaultSearchListModel<String> createModel() {
		DefaultSearchListModel<String> listModel = new DefaultSearchListModel<>();
		List<String> fruits = List.of("apple", "banana", "cherry", "date");
		listModel.add("fruits", fruits);

		List<String> veggies =
			List.of("artichoke", "beet", "cabbage", "dill");
		listModel.add("vegetables", veggies);

		return listModel;
	}

	private void choiceMade(String value, String category) {
		lastChoiceValue = value;
		lastChoiceCategory = category;
	}

	private void setFilterText(String text) {
		runSwing(() -> searchList.setFilterText(text));
	}
}
