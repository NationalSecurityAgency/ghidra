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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class ObjectRangeMapTest extends AbstractGenericTest {

	public ObjectRangeMapTest() {
		super();
	}
	
@Test
    public void testGetSet() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj = new Object();
		map.setObject(10,20,obj);
		assertEquals(null, map.getObject(0));
		assertEquals(null, map.getObject(9));
		assertEquals(obj, map.getObject(10));
		assertEquals(obj, map.getObject(20));
		assertEquals(null, map.getObject(21));
		
	}
@Test
    public void testGetSet2() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		Object obj2 = new Object();
		map.setObject(10,60,obj1);
		map.setObject(5,15,obj2);
		assertEquals(null, map.getObject(4));
		assertEquals(obj2, map.getObject(5));
		assertEquals(obj2, map.getObject(10));
		assertEquals(obj2, map.getObject(15));
		assertEquals(obj1, map.getObject(16));
		assertEquals(obj1, map.getObject(60));
		assertEquals(null, map.getObject(61));
		
	}
@Test
    public void testGetSet3() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		Object obj2 = new Object();
		map.setObject(10,60,obj1);
		map.setObject(55,65,obj2);
		assertEquals(null, map.getObject(9));
		assertEquals(obj1, map.getObject(10));
		assertEquals(obj1, map.getObject(54));
		assertEquals(obj2, map.getObject(55));
		assertEquals(obj2, map.getObject(60));
		assertEquals(obj2, map.getObject(65));
		assertEquals(null, map.getObject(66));
		
	}
@Test
    public void testGetSet4() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		Object obj2 = new Object();
		map.setObject(10,60,obj1);
		map.setObject(10,65,obj2);
		assertEquals(null, map.getObject(9));
		assertEquals(obj2, map.getObject(10));
		assertEquals(obj2, map.getObject(54));
		assertEquals(obj2, map.getObject(55));
		assertEquals(obj2, map.getObject(60));
		assertEquals(obj2, map.getObject(65));
		assertEquals(null, map.getObject(66));
		
	}
@Test
    public void testGetSet5() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		Object obj2 = new Object();
		map.setObject(10,60,obj1);
		map.setObject(5,60,obj2);
		assertEquals(null, map.getObject(4));
		assertEquals(obj2, map.getObject(5));
		assertEquals(obj2, map.getObject(54));
		assertEquals(obj2, map.getObject(55));
		assertEquals(obj2, map.getObject(60));
		assertEquals(null, map.getObject(61));
		
	}
@Test
    public void testGetSet6() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		Object obj2 = new Object();
		map.setObject(10,60,obj1);
		map.setObject(10,60,obj2);
		assertEquals(null, map.getObject(9));
		assertEquals(obj2, map.getObject(10));
		assertEquals(obj2, map.getObject(54));
		assertEquals(obj2, map.getObject(55));
		assertEquals(obj2, map.getObject(60));
		assertEquals(null, map.getObject(61));
	}
@Test
    public void testGetSet7() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		Object obj2 = new Object();
		map.setObject(10,60,obj1);
		map.setObject(20,50,obj2);
		assertEquals(null, map.getObject(9));
		assertEquals(obj1, map.getObject(10));
		assertEquals(obj1, map.getObject(19));
		assertEquals(obj2, map.getObject(20));
		assertEquals(obj2, map.getObject(50));
		assertEquals(obj1, map.getObject(51));
		assertEquals(obj1, map.getObject(60));
		assertEquals(null, map.getObject(61));
	}
@Test
    public void testGetSet8() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		Object obj2 = new Object();
		map.setObject(10,60,obj1);
		map.setObject(5, 65,obj2);
		assertEquals(null, map.getObject(4));
		assertEquals(obj2, map.getObject(5));
		assertEquals(obj2, map.getObject(9));
		assertEquals(obj2, map.getObject(10));
		assertEquals(obj2, map.getObject(60));
		assertEquals(obj2, map.getObject(61));
		assertEquals(obj2, map.getObject(65));
		assertEquals(null, map.getObject(66));
	}
@Test
    public void testGetSet9() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		Object obj2 = new Object();
		map.setObject(20,30,obj1);
		map.setObject(40,50,obj1);
		map.setObject(60,70,obj1);
		map.setObject(80,90,obj1);
		map.setObject(25,85, obj2);
		assertEquals(null, map.getObject(19));
		assertEquals(obj1, map.getObject(20));
		assertEquals(obj1, map.getObject(24));
		assertEquals(obj2, map.getObject(25));
		assertEquals(obj2, map.getObject(40));
		assertEquals(obj2, map.getObject(50));
		assertEquals(obj2, map.getObject(51));
		assertEquals(obj2, map.getObject(85));
		assertEquals(obj1, map.getObject(86));
		assertEquals(obj1, map.getObject(90));
		assertEquals(null, map.getObject(91));
	}
@Test
    public void testClear() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,50,obj1);
		map.clearRange(10,29);
		assertEquals(null, map.getObject(10));
		assertEquals(null, map.getObject(29));
		assertEquals(obj1, map.getObject(30));
		assertEquals(obj1, map.getObject(50));
		assertEquals(null, map.getObject(51));
	}
@Test
    public void testClear2() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,50,obj1);
		map.clearRange(41,60);
		assertEquals(null, map.getObject(19));
		assertEquals(obj1, map.getObject(20));
		assertEquals(obj1, map.getObject(40));
		assertEquals(null, map.getObject(41));
		assertEquals(null, map.getObject(50));
	}
@Test
    public void testClear3() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,50,obj1);
		map.clearRange(30,40);
		assertEquals(null, map.getObject(19));
		assertEquals(obj1, map.getObject(20));
		assertEquals(obj1, map.getObject(29));
		assertEquals(null, map.getObject(30));
		assertEquals(null, map.getObject(40));
		assertEquals(obj1, map.getObject(41));
		assertEquals(obj1, map.getObject(50));
		assertEquals(null, map.getObject(51));
	}
@Test
    public void testClear4() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,50,obj1);
		map.clearRange(10,60);
		assertEquals(null, map.getObject(19));
		assertEquals(null, map.getObject(20));
		assertEquals(null, map.getObject(29));
		assertEquals(null, map.getObject(30));
		assertEquals(null, map.getObject(40));
		assertEquals(null, map.getObject(41));
		assertEquals(null, map.getObject(50));
		assertEquals(null, map.getObject(51));
	}
@Test
    public void testClear5() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,50,obj1);
		map.clearRange(10,15);
		assertEquals(null, map.getObject(19));
		assertEquals(obj1, map.getObject(20));
		assertEquals(obj1, map.getObject(50));
		assertEquals(null, map.getObject(51));
	}
@Test
    public void testClear6() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,50,obj1);
		map.clearRange(70,80);
		assertEquals(null, map.getObject(19));
		assertEquals(obj1, map.getObject(20));
		assertEquals(obj1, map.getObject(50));
		assertEquals(null, map.getObject(51));
	}
@Test
    public void testClear7() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,50,obj1);
		map.clearRange(20,50);
		assertEquals(null, map.getObject(19));
		assertEquals(null, map.getObject(20));
		assertEquals(null, map.getObject(50));
		assertEquals(null, map.getObject(51));
	}
@Test
    public void testGetClear8() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,30,obj1);
		map.setObject(40,50,obj1);
		map.setObject(60,70,obj1);
		map.setObject(80,90,obj1);
		map.clearRange(25,85);
		assertEquals(null, map.getObject(19));
		assertEquals(obj1, map.getObject(20));
		assertEquals(obj1, map.getObject(24));
		assertEquals(null, map.getObject(25));
		assertEquals(null, map.getObject(40));
		assertEquals(null, map.getObject(50));
		assertEquals(null, map.getObject(51));
		assertEquals(null, map.getObject(85));
		assertEquals(obj1, map.getObject(86));
		assertEquals(obj1, map.getObject(90));
		assertEquals(null, map.getObject(91));
	}
	
@Test
    public void testContains() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,30,obj1);
		map.setObject(40,50,obj1);
		map.setObject(60,70,obj1);
		map.setObject(80,90,obj1);
		assertTrue(!map.contains(10));
		assertTrue(!map.contains(19));
		assertTrue( map.contains(20));
		assertTrue( map.contains(25));
		assertTrue( map.contains(30));
		assertTrue(!map.contains(31));
		assertTrue(!map.contains(39));
		assertTrue( map.contains(40));
		assertTrue(!map.contains(79));
		assertTrue( map.contains(80));
		assertTrue( map.contains(81));
		assertTrue( map.contains(89));
		assertTrue( map.contains(90));
		assertTrue(!map.contains(91));
		assertTrue(!map.contains(1000));
		
	}
@Test
    public void testIterator() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,30,obj1);
		map.setObject(40,50,obj1);
		map.setObject(60,70,obj1);
		map.setObject(80,90,obj1);

		IndexRangeIterator it = map.getIndexRangeIterator();
		assertTrue(it.hasNext());
		
		IndexRange range = it.next();
		assertEquals(20, range.getStart());
		assertEquals(30, range.getEnd());

		range = it.next();
		assertEquals(40, range.getStart());
		assertEquals(50, range.getEnd());

		range = it.next();
		assertEquals(60, range.getStart());
		assertEquals(70, range.getEnd());
	
		range = it.next();
		assertEquals(80, range.getStart());
		assertEquals(90, range.getEnd());
		
		assertTrue(!it.hasNext());
	}
@Test
    public void testIterator2() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,30,obj1);
		map.setObject(40,50,obj1);
		map.setObject(60,70,obj1);
		map.setObject(80,90,obj1);

		IndexRangeIterator it = map.getIndexRangeIterator(25, 85);
		assertTrue(it.hasNext());
		
		IndexRange range = it.next();
		assertEquals(25, range.getStart());
		assertEquals(30, range.getEnd());

		range = it.next();
		assertEquals(40, range.getStart());
		assertEquals(50, range.getEnd());

		range = it.next();
		assertEquals(60, range.getStart());
		assertEquals(70, range.getEnd());
	
		range = it.next();
		assertEquals(80, range.getStart());
		assertEquals(85, range.getEnd());
		
		assertTrue(!it.hasNext());
	}

@Test
    public void testIterator3() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,30,obj1);
		map.setObject(40,50,obj1);
		map.setObject(60,70,obj1);
		map.setObject(80,90,obj1);

		IndexRangeIterator it = map.getIndexRangeIterator(0,10);
		assertTrue(!it.hasNext());
		
	}
@Test
    public void testIterator4() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,30,obj1);
		map.setObject(40,50,obj1);
		map.setObject(60,70,obj1);
		map.setObject(80,90,obj1);

		IndexRangeIterator it = map.getIndexRangeIterator(100, 200);
		assertTrue(!it.hasNext());
		
	}
@Test
    public void testIterator5() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,30,obj1);
		map.setObject(40,50,obj1);
		map.setObject(60,70,obj1);
		map.setObject(80,90,obj1);

		IndexRangeIterator it = map.getIndexRangeIterator(40, 50);
		assertTrue(it.hasNext());
		
		IndexRange range = it.next();
		assertEquals(40, range.getStart());
		assertEquals(50, range.getEnd());

		assertTrue(!it.hasNext());
	}
@Test
    public void testIterator6() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,30,obj1);
		map.setObject(40,50,obj1);
		map.setObject(60,70,obj1);
		map.setObject(80,90,obj1);

		IndexRangeIterator it = map.getIndexRangeIterator(0,25);
		assertTrue(it.hasNext());
		
		IndexRange range = it.next();
		assertEquals(20, range.getStart());
		assertEquals(25, range.getEnd());

		assertTrue(!it.hasNext());
	}
@Test
    public void testIterator7() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,30,obj1);
		map.setObject(40,50,obj1);
		map.setObject(60,70,obj1);
		map.setObject(80,90,obj1);

		IndexRangeIterator it = map.getIndexRangeIterator(65,100);
		assertTrue(it.hasNext());
		
		IndexRange range = it.next();
		assertEquals(65, range.getStart());
		assertEquals(70, range.getEnd());

		range = it.next();
		assertEquals(80, range.getStart());
		assertEquals(90, range.getEnd());

		assertTrue(!it.hasNext());
	}
@Test
    public void testIterator8() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,30,obj1);
		map.setObject(40,50,obj1);
		map.setObject(60,70,obj1);
		map.setObject(80,90,obj1);

		IndexRangeIterator it = map.getIndexRangeIterator(42,48);
		assertTrue(it.hasNext());
		
		IndexRange range = it.next();
		assertEquals(42, range.getStart());
		assertEquals(48, range.getEnd());

		assertTrue(!it.hasNext());
	}
@Test
    public void testIterator9() {
		ObjectRangeMap<Object> map = new ObjectRangeMap<Object>();
		Object obj1 = new Object();
		map.setObject(20,30,obj1);
		map.setObject(40,50,obj1);
		map.setObject(60,70,obj1);
		map.setObject(80,90,obj1);

		IndexRangeIterator it = map.getIndexRangeIterator(35, 55);
		assertTrue(it.hasNext());
		
		IndexRange range = it.next();
		assertEquals(40, range.getStart());
		assertEquals(50, range.getEnd());

		assertTrue(!it.hasNext());
	}
}
