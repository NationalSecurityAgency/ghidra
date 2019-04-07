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
package ghidra.util.datastruct;

import static org.junit.Assert.assertTrue;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;

import org.junit.*;

import generic.test.AbstractGenericTest;

/**
 * Tests the {@link WeakSet} class.
 * 
 * 
 * @since  Tracker Id 522
 */
public class WeakSetTest extends AbstractGenericTest {

	/**
	 * Creates an instance of this test class with the provided test name.
	 * 
	 */
	public WeakSetTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

	}

	@After
	public void tearDown() throws Exception {

	}

//    /*
//     * Test method for 'ghidra.util.WeakSet.WeakSet(Class)'
//     */
//    public void testConstructor() {
//        // valid instantiation
//        new WeakSet();
//        
//        // invalid parameter test
//        try {
//            new WeakSet( null );
//            
//            Assert.fail( "Passing null to the WeakSet's constructor did not trigger " +
//                "a NullPointerException." );
//        } catch ( NullPointerException npe ) {
//            // good, expected
//        }
//    }

	/*
	 * Test method for 'ghidra.util.WeakSet.add(Object)' and
	 * 'ghidra.util.WeakSet.add(Object)'
	 */
	@Test
	public void testAddAndRemove() {
		WeakSet<String> weakSet = WeakDataStructureFactory.createCopyOnWriteWeakSet();

		String[] values = { "one", "two", "three" };

		// test add
		for (int i = 0; i < values.length; i++) {
			weakSet.add(values[i]);

			assertTrue("The weak set does not contain the correct number of " +
				"elements after calling add().", ((i + 1) == weakSet.size()));
		}

		// now test remove
		for (int i = 0; i < values.length; i++) {
			weakSet.remove(values[i]);

			assertTrue(
				"The weak set does not contain the correct number " +
					"of elements after calling remove().",
				((values.length - (i + 1)) == weakSet.size()));
		}
	}

	/*
	 * Test method for 'ghidra.util.WeakSet.clear()',
	 * 'ghidra.util.WeakSet.clear()' and 
	 * 'ghidra.util.WeakSet.isEmpty()'
	 */
	@Test
	public void testClear() {
		WeakSet<String> weakSet = WeakDataStructureFactory.createCopyOnWriteWeakSet();

		String[] values = { "one", "two", "three" };

		for (String value : values) {
			weakSet.add(value);
		}

		assertTrue("The weak set does not contain the correct number of " +
			"elements after calling add().", (values.length == weakSet.size()));

		weakSet.clear();

		assertTrue("The weak set does not have 0 elements after calling " + "clear().",
			(weakSet.size() == 0));

		assertTrue("WeakSet.isEmpty() did not return true when the set is " + "empty.",
			weakSet.isEmpty());
	}

//    /*
//     * Test method for 'ghidra.util.WeakSet.toArray()'
//     */
//    public void testToArray() {
//        WeakSet<String> weakSet = new WeakSet<String>();
//        
//        String[] values = { "one", "two", "three" };
//                
//        // test add
//        for (int i = 0; i < values.length; i++) {
//            weakSet.add( values[i] );
//        }
//        
//        assertTrue( "The weak set does not contain the correct number of " +
//            "elements after calling add().", (values.length==weakSet.size()) );
//        
//        Object[] valuesArray = weakSet.toArray();
//        
//        // check the array against our values
//        assertTrue( "The weak set returned a values array that is not the " +
//            "size as the number of values passed in.", 
//            (valuesArray.length==values.length) );
//        
//        List valuesList = new ArrayList( Arrays.asList( values ) );
//        for (int i = 0; i < valuesArray.length; i++) {
//            assertTrue( "An element returned from the weak set was not " +
//                "passed to the set.", valuesList.contains( valuesArray[i] ) );
//        }
//    }

	/*
	 * Test method for 'ghidra.util.WeakSet.getListeners()'
	 */
	@Test
	public void testGetListeners() {
		WeakSet<String> weakSet = WeakDataStructureFactory.createCopyOnWriteWeakSet();

		String[] values = { "one", "two", "three" };

		// test add
		for (String value : values) {
			weakSet.add(value);
		}

		assertTrue("The weak set does not contain the correct number of " +
			"elements after calling add().", (values.length == weakSet.size()));

		Iterator<String> iterator = weakSet.iterator();

		// check the array against our values
		int elementCount = 0;
		List<String> valuesList = new ArrayList<String>(Arrays.asList(values));
		for (; iterator.hasNext(); elementCount++) {
			assertTrue("An element returned from the weak set was not " + "passed to the set.",
				valuesList.contains(iterator.next()));
		}

		assertTrue("The weak set returned a values array that is not the " +
			"size as the number of values passed in.", (elementCount == values.length));
	}

// Commented out because it was slow
//	public void testReferencesRemovedAfterCollection() {
//		// create some references and hold on to them to make sure that
//		// they are not collected and stay in the set
//		WeakSet<ActionListener> weakSet = WeakDataStructureFactory.createCopyOnWriteWeakSet();
//
//		ActionListener[] values =
//			new ActionListener[] { new ActionListenerAdapter(), new ActionListenerAdapter(),
//				new ActionListenerAdapter(), new ActionListenerAdapter() };
//
//		// test add
//		for (int i = 0; i < values.length; i++) {
//			weakSet.add(values[i]);
//		}
//
//		assertTrue("The weak set does not contain the correct number of "
//			+ "elements after calling add().", (values.length == weakSet.size()));
//
//		// now release *all* those references
//		values = null;
//
//		// force garbage collection 
//		forceGarbageCollection();
//
//		// make sure that the unreferenced objects are removed from the set
//		assertTrue("The elements added to the weak set were not removed "
//			+ "when they were no longer referenced.", (0 == weakSet.size()));
//
//		// now try the test again while only deleting some of the values
//		values =
//			new ActionListener[] { new ActionListenerAdapter(), new ActionListenerAdapter(),
//				new ActionListenerAdapter(), new ActionListenerAdapter() };
//
//		for (int i = 0; i < values.length; i++) {
//			weakSet.add(values[i]);
//		}
//
//		assertTrue("The weak set does not contain the correct number of "
//			+ "elements after calling add().", (values.length == weakSet.size()));
//
//		// null out some values
//		values[0] = null;
//		values[2] = null;
//
//		// force garbage collection 
//		forceGarbageCollection();
//
//		// make sure that the unreferenced objects are removed from the set
//		assertTrue("The elements added to the weak set were not removed "
//			+ "when they were no longer referenced.", (2 == weakSet.size()));
//	}
//
	class ActionListenerAdapter implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent event) {
			// stub implementation
		}
	}

//	private void forceGarbageCollection() {
//		waitForPostedSwingRunnables();
//		System.gc();
//		System.gc();
//		try {
//			Thread.sleep(1000);
//		}
//		catch (Exception e) {
//			e.printStackTrace();
//		}
//		System.gc();
//		System.gc();
//		try {
//			Thread.sleep(1000);
//		}
//		catch (Exception e) {
//			e.printStackTrace();
//		}
//	}
}
