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
package docking;

import static org.junit.Assert.*;

import java.util.Set;

import javax.swing.JComponent;
import javax.swing.JLabel;

import org.junit.Test;

import docking.widgets.label.GDLabel;
import generic.test.AbstractGenericTest;

public class PlaceholderSetTest extends AbstractGenericTest {

	public PlaceholderSetTest() {
		super();
	}

	@Test
	public void testDedupingRestoredPlaceholders_OnlyOneHidden() {
		PlaceholderSet set = new PlaceholderSet(new PlaceholderManager(new DummyInstaller()));
		set.addRestoredPlaceholder(createPlaceholder("A", "1", false));

		Set<ComponentPlaceholder> placeholders = set.getUnusedPlaceholders();
		assertEquals(1, placeholders.size());
		assertTrue(contains(placeholders, "A", "1"));
	}

	@Test
	public void testRegisterPlaceholders_BrandNew() {
		PlaceholderSet set = new PlaceholderSet(new PlaceholderManager(new DummyInstaller()));
		ComponentPlaceholder placeholder = createPlaceholder("A", "1", true);

		TestProvider provider = new TestProvider();
		set.placeholderUsed(provider, placeholder);
		assertTrue(set.getUnusedPlaceholders().isEmpty());
		assertEquals(placeholder, set.getPlaceholder(provider));
		assertTrue(set.containsPlaceholder(provider));
	}

	@Test
	public void testRegisterPlaceholders_WasInUnusedList() {
		PlaceholderSet set = new PlaceholderSet(new PlaceholderManager(new DummyInstaller()));
		ComponentPlaceholder placeholder = createPlaceholder("A", "1", true);
		set.addRestoredPlaceholder(placeholder);

		TestProvider provider = new TestProvider();
		set.placeholderUsed(provider, placeholder);
		assertTrue(set.getUnusedPlaceholders().isEmpty());
		assertEquals(placeholder, set.getPlaceholder(provider));
		assertTrue(set.containsPlaceholder(provider));
	}

	@Test
	public void testFreePlaceholders() {
		PlaceholderSet set = new PlaceholderSet(new PlaceholderManager(new DummyInstaller()));
		ComponentPlaceholder placeholder = createPlaceholder("A", "1", true);

		TestProvider provider = new TestProvider();
		set.placeholderUsed(provider, placeholder);
		assertTrue(set.getUnusedPlaceholders().isEmpty());
		assertEquals(placeholder, set.getPlaceholder(provider));
		assertTrue(set.containsPlaceholder(provider));

		set.placeholderFreed(provider);
		assertEquals(1, set.getUnusedPlaceholders().size());
		assertNull(set.getPlaceholder(provider));
	}

	private boolean contains(Set<ComponentPlaceholder> set, String name, String title) {
		for (ComponentPlaceholder placeholder : set) {
			if (placeholder.getName().equals(name) && placeholder.getTitle().equals(title)) {
				return true;
			}
		}
		return false;
	}

	private ComponentPlaceholder createPlaceholder(String name, String title, boolean show) {
		return new ComponentPlaceholder(name, "owner", "group", title, show, null, 0);
	}

//=================================================================================================
// Inner Classes	
//=================================================================================================	

	private class DummyInstaller implements PlaceholderInstaller {

		@Override
		public void installPlaceholder(ComponentPlaceholder placeholder, WindowPosition position) {
			// dummy
		}

		@Override
		public void uninstallPlaceholder(ComponentPlaceholder placeholder, boolean keepAround) {
			// dummy
		}
	}

	private class TestProvider extends ComponentProvider {
		JLabel label = new GDLabel();

		public TestProvider() {
			super(null, null, null);
		}

		@Override
		public JComponent getComponent() {
			return label;
		}
	}
}
