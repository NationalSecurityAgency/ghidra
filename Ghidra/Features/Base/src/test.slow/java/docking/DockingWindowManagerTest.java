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

import static docking.WindowPosition.*;
import static org.junit.Assert.*;

import java.awt.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JComponent;
import javax.swing.JLabel;

import org.jdom.Element;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.label.GDLabel;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.test.DummyTool;

public class DockingWindowManagerTest extends AbstractDockingTest {

	private Tool tool = new DummyTool();

	@Test
	public void testDefaultGroupWindowPosition() {
		//
		// Test that each new provider, with different groups, gets placed in its preferred
		// default window position.
		//

		DockingWindowManager dwm = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider providerA = addProvider(dwm, "A", "a", RIGHT);
		ComponentProvider providerB = addProvider(dwm, "B", "b", BOTTOM);
		ComponentProvider providerC = addProvider(dwm, "C", "c", LEFT);

		show(dwm);

		assertTotheRight(dwm, providerA, providerC);
		assertAbove(dwm, providerA, providerB);
		assertAbove(dwm, providerC, providerB);
	}

	@Test
	public void testSameGroupWindowPosition_Stacked() {
		//
		// Test that each new provider, with the same group, gets placed in its preferred
		// intragroup window position.  Note: 'Stacked' is the default.
		//

		DockingWindowManager dwm = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider providerA1 = addProvider(dwm, "A1", "a", RIGHT, STACK);
		ComponentProvider providerA2 = addProvider(dwm, "A2", "a", BOTTOM, STACK);
		ComponentProvider providerA3 = addProvider(dwm, "A3", "a", LEFT, STACK);

		show(dwm);

		assertStacked(dwm, providerA1, providerA2, providerA3);
	}

	@Test
	public void testSameGroupWindowPosition_Bottom() {
		//
		// Test that each new provider, with the same group, gets placed in its preferred
		// intragroup window position.
		//

		DockingWindowManager dwm = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider providerA1 = addProvider(dwm, "A1", "a", RIGHT, STACK);
		ComponentProvider providerA2 = addProvider(dwm, "A2", "a", LEFT, BOTTOM);

		show(dwm);

		assertAbove(dwm, providerA1, providerA2);
	}

	@Test
	public void testSameGroupWindowPosition_Window() {
		//
		// Test that each new provider, with the same group, gets placed in its preferred
		// intragroup window position.
		//

		DockingWindowManager dwm = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider providerA1 = addProvider(dwm, "A1", "a", RIGHT, WINDOW);
		ComponentProvider providerA2 = addProvider(dwm, "A2", "a", LEFT, WINDOW);

		show(dwm);

		// Note: the windows are the same, as the intragroup position of 'window' is ignored
		assertSameWindows(dwm, providerA1, providerA2);
	}

	@Test
	public void testRelativeGroupWindowPosition_Stacked() {
		//
		// Test that each new provider, with a group that has a partial match to another group,
		//gets placed in its preferred intragroup position.
		// 
		// Note: 'Stacked' is the default.
		//

		// note: the positions specified here are for default positions, not intragroup positions
		DockingWindowManager dwm = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider providerA = addProvider(dwm, "A", "a", RIGHT, STACK);
		ComponentProvider providerAB = addProvider(dwm, "AB", "a.b", BOTTOM, STACK);
		ComponentProvider providerABC = addProvider(dwm, "ABC", "a.b.c", LEFT, STACK);

		show(dwm);

		assertStacked(dwm, providerA, providerAB, providerABC);
	}

	@Test
	public void testRelativeGroupWindowPosition_Mixed() {
		//
		// Test that each new provider, with a group that has a partial match to another group,
		//gets placed in its preferred intragroup position.
		// 
		// Note: 'Stacked' is the default.
		//

		// note: the positions specified here are for default positions, not intragroup positions
		DockingWindowManager dwm = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider providerA = addProvider(dwm, "A", "a", RIGHT, BOTTOM);
		ComponentProvider providerAB = addProvider(dwm, "AB", "a.b", BOTTOM, TOP);
		ComponentProvider providerABC = addProvider(dwm, "ABC", "a.b.c", LEFT, RIGHT);

		show(dwm);

		/*    
		  
		   We are expecting a layout something like this (although exact layout may change
		   due to memory layout):
		 	
		 	
		 		.=========.=========.
		 		|         |         |
		 		|  AB     |  ABC    |
		 		|         |         |
		 		.===================.
		 		|                   |
		 		|         A         |
		 		|                   |
		 		.===================.
		 
		 
		 */

		assertAbove(dwm, providerAB, providerA);
		assertAbove(dwm, providerABC, providerA);
		assertTotheRight(dwm, providerABC, providerAB);
	}

	@Test
	public void testRestoreFromXML_UnrelatedGroups() {
		//
		// Test that, for unrelated groups, the layout info stored in XML is re-used when providers
		// are shown after that XML is restored--even if the window positioning changes
		//
		final DockingWindowManager dwm1 = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider providerA = addProvider(dwm1, "A", "a", RIGHT);
		ComponentProvider providerB = addProvider(dwm1, "B", "b", BOTTOM);
		ComponentProvider providerC = addProvider(dwm1, "C", "c", LEFT);

		show(dwm1);

		// sanity check
		assertAbove(dwm1, providerA, providerB);
		assertTotheRight(dwm1, providerB, providerC);

		Element element = new Element("TEST");
		dwm1.saveToXML(element);
		final DockingWindowManager dwm2 = createNewDockingWindowManagerFromXML(element);

		//
		// Show providers that have the same name and group as those we just added above.  Make 
		// sure that even though they are changing the window positions, they will still 
		// be placed where they were when the xml was saved.
		//
		ComponentProvider newB = addProvider(dwm2, "B", "b", WINDOW, STACK);
		ComponentProvider newA = addProvider(dwm2, "A", "a", WINDOW, STACK);
		ComponentProvider newC = addProvider(dwm2, "C", "c", WINDOW, STACK);

		assertAbove(dwm2, newA, newB);
		assertTotheRight(dwm2, newB, newC);
	}

	@Test
	public void testRestoreFromXML_RelativeGroups() {
		//
		// Test that, for related groups, the layout info stored in XML is re-used when providers
		// are shown after that XML is restored--even if the window positioning changes
		//
		DockingWindowManager dwm1 = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider providerA = addProvider(dwm1, "A", "a", RIGHT);
		ComponentProvider providerAB = addProvider(dwm1, "AB", "a.b", BOTTOM);
		ComponentProvider providerABC = addProvider(dwm1, "ABC", "a.b.c", LEFT);

		show(dwm1);

		// sanity check
		assertAbove(dwm1, providerA, providerAB);
		assertTotheRight(dwm1, providerAB, providerABC);

		Element element = new Element("TEST");
		dwm1.saveToXML(element);
		DockingWindowManager dwm2 = createNewDockingWindowManagerFromXML(element);

		//
		// Show providers that have the same name and group as those we just added above.  Make 
		// sure that even though they are changing the window positions, they will still 
		// be placed where they were when the xml was saved.
		//
		ComponentProvider newAB = addProvider(dwm2, "AB", "a.b", WINDOW, STACK);
		ComponentProvider newA = addProvider(dwm2, "A", "a", WINDOW, STACK);
		ComponentProvider newABC = addProvider(dwm2, "ABC", "a.b.c", WINDOW, STACK);

		assertAbove(dwm2, newA, newAB);
		assertTotheRight(dwm2, newAB, newABC);
	}

	@Test
	public void testRestoreFromXML_favorVisiblePlaceholder() {
		//
		// Tests that the xml restore doesn't throw away 
		DockingWindowManager dwm1 = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider provider1 = addProvider(dwm1, "A", "a", "X", STACK);
		ComponentProvider provider2 = addProvider(dwm1, "A", "a", "X", STACK);
		moveWindow(dwm1, provider1, provider2, RIGHT);

		show(dwm1);

//		dwm1.showComponent(provider1, false);
		dwm1.showComponent(provider2, false);

		Element element = new Element("TEST");
		dwm1.saveToXML(element);

		dwm1.showComponent(provider1, false);

		final DockingWindowManager dwm2 =
			new DockingWindowManager(new DummyTool("Tool2"), (List<Image>) null);
		ComponentProvider newProvider = addProvider(dwm2, "A", "a", "X", STACK);

		runSwing(() -> {
			dwm2.setVisible(true);
			dwm2.restoreFromXML(element);
		});
		waitForSwing();
		assertTrue(dwm2.isVisible(newProvider));

	}

	@Test
	public void testRestoreFromXML_duplicateNameAndGroup() {
		//
		// Test that, for related groups, the layout info stored in XML is re-used when providers
		// are shown after that XML is restored--even if the window positioning changes
		//
		DockingWindowManager dwm1 = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider providerX = addProvider(dwm1, "A", "a", "X", STACK);
		ComponentProvider providerY = addProvider(dwm1, "A", "a", "Y", STACK);
		ComponentProvider providerZ = addProvider(dwm1, "A", "a", "Z", STACK);

		show(dwm1);

		moveWindow(dwm1, providerX, providerY, RIGHT);
		moveWindow(dwm1, providerX, providerZ, BOTTOM);

		// sanity check
		assertAbove(dwm1, providerX, providerZ);
		assertTotheRight(dwm1, providerY, providerX);

		Element element = new Element("TEST");
		dwm1.saveToXML(element);
		DockingWindowManager dwm2 = createNewDockingWindowManagerFromXML(element);

		//
		// Show providers that have the same name and group as those we just added above.  Make 
		// sure that even though they are changing the window positions, they will still 
		// be placed where they were when the xml was saved.
		//
		ComponentProvider newX = addProvider(dwm2, "A", "a", "X", STACK);
		ComponentProvider newY = addProvider(dwm2, "A", "a", "Y", STACK);
		ComponentProvider newZ = addProvider(dwm2, "A", "a", "Z", STACK);

		assertAbove(dwm2, newX, newZ);
		assertTotheRight(dwm2, newY, newX);
	}

	@Test
	public void testParentGroupToSubGroupRelationship_ParentOpenFirst() {
		//
		// Test that a parent group 'a' will always open where it wants to, relative to its group, 
		// and that a subgroup 'a.b' will open relative to the parent.  **Make sure that this
		// works when the parent is the first provider open.
		//
		DockingWindowManager dwm = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider providerA = addProvider(dwm, "A", "a", TOP, RIGHT);
		ComponentProvider providerAB = addProvider(dwm, "AB", "a.b", RIGHT, BOTTOM);

		show(dwm);

		assertAbove(dwm, providerA, providerAB);
	}

	@Test
	public void testParentGroupToSubGroupRelationship_ChildOpenFirst() {
		//
		// Test that a parent group 'a' will always open where it wants to, relative to its group, 
		// and that a subgroup 'a.b' will open relative to the parent.  **Make sure that this
		// works when the subgroup is the first provider open.
		//
		DockingWindowManager dwm = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider providerAB = addProvider(dwm, "AB", "a.b", RIGHT, BOTTOM);
		ComponentProvider providerA = addProvider(dwm, "A", "a", TOP, RIGHT);

		show(dwm);

		// Parent is still above the child (it's default position is used), since the 
		// parent 'a' is not a child of 'a.b'
		assertAbove(dwm, providerA, providerAB);
	}

	@Test
	public void testGroupPositioningAcrossOwnwers() {
		//
		// Test that two providers that don't share an owner (the plugin) can share a group and 
		// open relative to each other.
		//
		DockingWindowManager dwm = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider p1 = addProvider(dwm, "Owner_1", "Name_1", "group", TOP, TOP);
		ComponentProvider p2 = addProvider(dwm, "Owner_2", "Name_2", "group", BOTTOM, RIGHT);

		show(dwm);

		// the provider shown last is the intragroup that is used
		assertTotheRight(dwm, p2, p1);
	}

	@Test
	public void testGroupPositioning_SCR_10248() {
		/*    
		  
		   We are expecting a layout something like this (although exact layout may change
		   due to memory layout):
		 	
		 	
		 		We want this:
		 		
		 		
		 		.=========.=========.=========.
		 		|         |         |         |
		 		|    A    |    B    |    C    |
		 		|         .=========.         |
		 		|         |         |         |
		 		|         |    B2   |         |
		 		.=========.=========.=========.
		 		
		 		
		 		Not this:
		 	
		 	
		 		.=========.=========.=========.
		 		|         |         |         |
		 		|    A    |    B    |    C    |
		 		|         |         |         |
		 		|         |         |         |
		 		|         |         |         |
		 		.=============================.
		 		|                             |
		 		|              B2             |
		 		|                             |
		 		.=============================.
		 
		 
		 */

		DockingWindowManager dwm = new DockingWindowManager(tool, (List<Image>) null);

		ComponentProvider pA = addProvider(dwm, "Owner_1", "A", "a", LEFT, LEFT);
		ComponentProvider pB = addProvider(dwm, "Owner_2", "B", "b", RIGHT, RIGHT);
		ComponentProvider pC = addProvider(dwm, "Owner_3", "C", "c", RIGHT, RIGHT);

		ComponentProvider pB2 = addProvider(dwm, "Owner_4", "B2", "b.2", BOTTOM, BOTTOM);

		show(dwm);

		// note: as in the picture above, B and B2 are in the same column
		assertTotheRight(dwm, pB, pA);
		assertTotheRight(dwm, pB2, pA);

		assertTotheRight(dwm, pC, pB);
		assertTotheRight(dwm, pC, pB2);

		assertAbove(dwm, pB, pB2);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void show(final DockingWindowManager manager) {
		runSwing(() -> manager.setVisible(true));
		waitForSwing();
	}

	//@formatter:off
	private ComponentProvider addProvider(final DockingWindowManager dwm, 
							 final String name, 
							 final String group,
							 final WindowPosition defaultWindowPosition) {
		
		return addProvider(dwm, "SomeOwner", name, group, defaultWindowPosition, defaultWindowPosition);
	}
	//@formatter:on
	//@formatter:off
	private ComponentProvider addProvider(final DockingWindowManager dwm, 
							 final String name, 
							 final String group,
							 final String title,
							 final WindowPosition defaultWindowPosition) {
		
		return addProvider(dwm, "SomeOwner", name, group, title, defaultWindowPosition, defaultWindowPosition);
	}
	//@formatter:on

	//@formatter:off
	private ComponentProvider addProvider(final DockingWindowManager dwm, 
							 final String name, 
							 final String group,
							 final WindowPosition defaultWindowPosition, 
							 final WindowPosition defaultIntragroupPoistion) {
		
		return addProvider(dwm, "SomeOwner", name, group, defaultWindowPosition, defaultIntragroupPoistion);
	}
	//@formatter:on

	//@formatter:off
	private ComponentProvider addProvider(final DockingWindowManager dwm, 
						 	 final String owner, 
							 final String name, 
							 final String group,
							 final WindowPosition defaultWindowPosition, 
							 final WindowPosition defaultIntragroupPoistion) {
		return addProvider(dwm, owner, name, group, "Default Title", defaultWindowPosition,
				defaultIntragroupPoistion);
	}
	//@formatter:on

	//@formatter:off
	private ComponentProvider addProvider(final DockingWindowManager dwm, 
						 	 final String owner, 
							 final String name, 
							 final String group,
							 final String title,
							 final WindowPosition defaultWindowPosition, 
							 final WindowPosition defaultIntragroupPoistion) {
		
		final AtomicReference<ComponentProvider> ref = new AtomicReference<>();
		runSwing(() -> {
			ComponentProvider p = new MyProvider(owner, name, group, title, defaultWindowPosition);
			p.setIntraGroupPosition(defaultIntragroupPoistion);
			dwm.addComponent(p, true);
			ref.set(p);
		});
		waitForSwing();
		
		return ref.get();
	}
	//@formatter:on

	private DockingWindowManager createNewDockingWindowManagerFromXML(final Element element) {
		final DockingWindowManager dwm2 =
			new DockingWindowManager(new DummyTool("Tool2"), (List<Image>) null);

		runSwing(() -> {
			dwm2.setVisible(true);
			dwm2.restoreFromXML(element);
		});
		return dwm2;
	}

	private void assertSameWindows(DockingWindowManager dwm, ComponentProvider p1,
			ComponentProvider p2) {
		ComponentPlaceholder ph1 = dwm.getActivePlaceholder(p1);
		ComponentPlaceholder ph2 = dwm.getActivePlaceholder(p2);

		ComponentNode n1 = ph1.getNode();
		ComponentNode n2 = ph2.getNode();

		JComponent c1 = n1.getComponent();
		JComponent c2 = n2.getComponent();

		Window w1 = windowForComponent(c1);
		Window w2 = windowForComponent(c2);
		assertEquals(w1, w2);
	}

	private void moveWindow(DockingWindowManager dwm, ComponentProvider p1, ComponentProvider p2,
			WindowPosition position) {
		runSwing(() -> {
			ComponentPlaceholder ph1 = dwm.getActivePlaceholder(p1);
			ComponentPlaceholder ph2 = dwm.getActivePlaceholder(p2);
			ComponentNode n1 = ph1.getNode();
			ComponentNode n2 = ph2.getNode();
			n2.remove(ph2);
			n1.split(ph2, position);
		});
		waitForSwing();
	}

	private void assertAbove(DockingWindowManager dwm, ComponentProvider p1, ComponentProvider p2) {
		ComponentPlaceholder ph1 = dwm.getActivePlaceholder(p1);
		ComponentPlaceholder ph2 = dwm.getActivePlaceholder(p2);

		ComponentNode n1 = ph1.getNode();
		ComponentNode n2 = ph2.getNode();

		JComponent c1 = n1.getComponent();
		JComponent c2 = n2.getComponent();

		Point l1 = c1.getLocationOnScreen();
		Point l2 = c2.getLocationOnScreen();
		assertTrue(
			"Provider is not above the other provider.  " + p1.getName() + " / " + p2.getName(),
			l1.y < l2.y);
	}

	private void assertTotheRight(DockingWindowManager dwm, ComponentProvider p1,
			ComponentProvider p2) {
		ComponentPlaceholder ph1 = dwm.getActivePlaceholder(p1);
		ComponentPlaceholder ph2 = dwm.getActivePlaceholder(p2);

		ComponentNode n1 = ph1.getNode();
		ComponentNode n2 = ph2.getNode();

		JComponent c1 = n1.getComponent();
		JComponent c2 = n2.getComponent();

		Point l1 = c1.getLocationOnScreen();
		Point l2 = c2.getLocationOnScreen();
		assertTrue("Provider is not to the right of the other provider.  " + p1.getName() + " / " +
			p2.getName(), l1.x > l2.x);
	}

	private void assertStacked(DockingWindowManager dwm, ComponentProvider... providers) {

		Integer x = null;
		Integer y = null;

		for (ComponentProvider p : providers) {

			ComponentPlaceholder ph = dwm.getActivePlaceholder(p);
			ComponentNode n = ph.getNode();
			JComponent c = n.getComponent();
			Point l = c.getLocationOnScreen();

			if (x == null) {
				x = l.x;
				y = l.y;
			}
			else {
				assertEquals("Providers are not stacked together", x.intValue(), l.x);
				assertEquals("Providers are not stacked together", y.intValue(), l.y);
			}

		}
	}

	class MyProvider extends ComponentProviderAdapter {
		JLabel label = new GDLabel();

		public MyProvider(String owner, String name, String group, String title,
				WindowPosition defaultWindowPosition) {
			super(null, name, owner);
			setWindowGroup(group);
			setDefaultWindowPosition(defaultWindowPosition);
			setTitle(title);
		}

		@Override
		public JComponent getComponent() {
			return label;
		}
	}

}
