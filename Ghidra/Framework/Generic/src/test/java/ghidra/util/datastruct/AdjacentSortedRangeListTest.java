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

import java.util.Iterator;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;


public class AdjacentSortedRangeListTest extends AbstractGenericTest {
	private AdjacentSortedRangeList list;
	/**
	 * 
	 */
	public AdjacentSortedRangeListTest() {
		super();
	}
	
	
    @Before
    public void setUp() throws Exception {
		list = new AdjacentSortedRangeList();
	}
@Test
    public void testAdd1() {
		list.addRange(5, 7);
		assertEquals(1, list.getNumRanges());
		assertEquals(new Range(5, 7), list.getRanges().next());
		
		list.addRange(20, 22);
		assertEquals(2, list.getNumRanges());
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range(5, 7), it.next());
		assertEquals(new Range(20, 22), it.next());
		
		list.addRange(0,2);
		assertEquals(3, list.getNumRanges());
		it = list.getRanges();
		assertEquals(new Range(0, 2), it.next());
		assertEquals(new Range(5, 7), it.next());
		assertEquals(new Range(20, 22), it.next());
		
		list.addRange(12,12);
		assertEquals(4, list.getNumRanges());
		it = list.getRanges();
		assertEquals(new Range(0, 2), it.next());
		assertEquals(new Range(5, 7), it.next());
		assertEquals(new Range(12, 12), it.next());
		assertEquals(new Range(20, 22), it.next());
		
		list.addRange(23,27);
		assertEquals(5, list.getNumRanges());
		it = list.getRanges();
		assertEquals(new Range(0, 2), it.next());
		assertEquals(new Range(5, 7), it.next());
		assertEquals(new Range(12, 12), it.next());
		assertEquals(new Range(20, 22), it.next());
		assertEquals(new Range(23, 27), it.next());
		
		list.addRange(3,4);
		assertEquals(6, list.getNumRanges());
		it = list.getRanges();
		assertEquals(new Range(0, 2), it.next());
		assertEquals(new Range(3, 4), it.next());
		assertEquals(new Range(5, 7), it.next());
		assertEquals(new Range(12, 12), it.next());
		assertEquals(new Range(20, 22), it.next());
		assertEquals(new Range(23, 27), it.next());
	}
@Test
    public void testAdd2() {
		list.addRange(3,7);
		list.addRange(4,10);
		assertEquals(1, list.getNumRanges());
		assertEquals(new Range(3, 10), list.getRanges().next());
	}
@Test
    public void testAdd3() {
		list.addRange(4,10);
		list.addRange(3, 7);
		assertEquals(1, list.getNumRanges());
		assertEquals(new Range(3, 10), list.getRanges().next());
	}
@Test
    public void testAdd4() {
		list.addRange(3,7);
		list.addRange(8,10);
		assertEquals(2, list.getNumRanges());
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range(3,  7), it.next());
		assertEquals(new Range(8, 10), it.next());
	}
@Test
    public void testAdd5() {
		list.addRange(8,10);
		list.addRange(3,7);
		assertEquals(2, list.getNumRanges());
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range(3,  7), it.next());
		assertEquals(new Range(8, 10), it.next());
	}
	
@Test
    public void testAdd6() {
		list.addRange(3,7);
		list.addRange(8,10);
		list.addRange(4,12);
		assertEquals(1, list.getNumRanges());
		assertEquals(new Range(3, 12), list.getRanges().next());
	}
@Test
    public void testAdd7() {
		list.addRange(12, 20);
		list.addRange(14, 16);
		assertEquals(1, list.getNumRanges());
		assertEquals(new Range(12, 20), list.getRanges().next());
	}	
@Test
    public void testAdd8() {
		list.addRange(0,4);
		list.addRange(6, 10);
		assertEquals(2, list.getNumRanges());
		list.addRange(5,5);
		assertEquals(3, list.getNumRanges());
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range(0, 4), it.next());
		assertEquals(new Range(5, 5), it.next());
		assertEquals(new Range(6, 10), it.next());
	}	
@Test
    public void testAddNegFirst() {
		list.addRange(-20480, -20352); // -20480, -20352
		list.addRange(-16384, -15824); //
		list.addRange(-16128, -15616);
		list.addRange(-12288, -12235);
		list.addRange(-12234, -12224);
		list.addRange(-8192, 184565760);
		assertEquals(5, list.getNumRanges());
		assertEquals(new Range(-20480, -20352), list.getRange(0));
		assertEquals(new Range(-16384, -15616), list.getRange(1));
		assertEquals(new Range(-12288, -12235), list.getRange(2));
		assertEquals(new Range(-12234, -12224), list.getRange(3));
		assertEquals(new Range(-8192, 184565760), list.getRange(4));
		list.addRange(5,5);
		list.addRange(201334784, 201338880);
		assertEquals(6, list.getNumRanges());
		assertEquals(new Range(-20480, -20352), list.getRange(0));
		assertEquals(new Range(-16384, -15616), list.getRange(1));
		assertEquals(new Range(-12288, -12235), list.getRange(2));
		assertEquals(new Range(-12234, -12224), list.getRange(3));
		assertEquals(new Range(-8192, 184565760), list.getRange(4));
		assertEquals(new Range(201334784, 201338880), list.getRange(5));
	}	
@Test
    public void testAddPosFirst() {
		list.addRange(0, 4);
		list.addRange(6, 10);
		list.addRange(3500, 4400);
		list.addRange(135676, 149987);
		assertEquals(4, list.getNumRanges());
		assertEquals(new Range(0, 4), list.getRange(0));
		assertEquals(new Range(6, 10), list.getRange(1));
		assertEquals(new Range(3500, 4400), list.getRange(2));
		assertEquals(new Range(135676, 149987), list.getRange(3));

		list.addRange(-20480, -20352);
		list.addRange(-16384, -15824);
		list.addRange(-16128, -15616);
		list.addRange(-12288, -12235);
		list.addRange(-12234, -12224);
		list.addRange(-8192, 3);
		assertEquals(8, list.getNumRanges());
		assertEquals(new Range(-20480, -20352), list.getRange(0));
		assertEquals(new Range(-16384, -15616), list.getRange(1));
		assertEquals(new Range(-12288, -12235), list.getRange(2));
		assertEquals(new Range(-12234, -12224), list.getRange(3));
		assertEquals(new Range(-8192, 4), list.getRange(4));
		assertEquals(new Range(6, 10), list.getRange(5));
		assertEquals(new Range(3500, 4400), list.getRange(6));
		assertEquals(new Range(135676, 149987), list.getRange(7));
		
		list.addRange(4200, 4800);
		list.addRange(149988, 150000);
		assertEquals(9, list.getNumRanges());
		assertEquals(new Range(-20480, -20352), list.getRange(0));
		assertEquals(new Range(-16384, -15616), list.getRange(1));
		assertEquals(new Range(-12288, -12235), list.getRange(2));
		assertEquals(new Range(-12234, -12224), list.getRange(3));
		assertEquals(new Range(-8192, 4), list.getRange(4));
		assertEquals(new Range(6, 10), list.getRange(5));
		assertEquals(new Range(3500, 4800), list.getRange(6));
		assertEquals(new Range(135676, 149987), list.getRange(7));
		assertEquals(new Range(149988, 150000), list.getRange(8));
	}	
@Test
    public void testRemove1() {
		list.addRange(0,10);
		list.removeRange(5,5);
		assertEquals(2, list.getNumRanges());
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range(0, 4), it.next());
		assertEquals(new Range(6, 10), it.next());
	}
@Test
    public void testRemove2() {
		list.addRange(0,2);
		list.addRange(6,8);
		list.addRange(12, 14);
		list.removeRange(6,7);
		assertEquals(3, list.getNumRanges());
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range(0, 2), it.next());
		assertEquals(new Range(8, 8), it.next());
		assertEquals(new Range(12, 14), it.next());
	}
@Test
    public void testRemove3() {
		list.addRange(0,2);
		list.addRange(6,8);
		list.addRange(12, 14);
		list.removeRange(1,50);
		assertEquals(1, list.getNumRanges());
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range(0, 0), it.next());
	}
@Test
    public void testRemove4() {
		list.addRange(0,2);
		list.addRange(6,8);
		list.addRange(12, 14);
		list.removeRange(0,11);
		assertEquals(1, list.getNumRanges());
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range(12, 14), it.next());
	}
@Test
    public void testRemove5() {
		list.addRange(0,4);
		list.addRange(5,10);
		list.removeRange(5,5);
		assertEquals(2, list.getNumRanges());
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range(0, 4), it.next());
		assertEquals(new Range(6, 10), it.next());
	}	
@Test
    public void testRemove6() {
		list.addRange(0,4);
		list.addRange(7,10);
		list.removeRange(5,5);
		assertEquals(2, list.getNumRanges());
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range(0, 4), it.next());
		assertEquals(new Range(7, 10), it.next());
	}	
@Test
    public void testRemove7() {
		list.addRange(0,4);
		list.addRange(7,10);
		list.addRange(11,14);
		list.addRange(25,30);
		list.addRange(40,44);
		list.addRange(45,49);
		assertEquals(6, list.getNumRanges());
		list.removeRange(26,27);
		list.removeRange(38,52);
		list.removeRange(3,8);
		assertEquals(5, list.getNumRanges());
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range( 0,  2), it.next());
		assertEquals(new Range( 9, 10), it.next());
		assertEquals(new Range(11, 14), it.next());
		assertEquals(new Range(25, 25), it.next());
		assertEquals(new Range(28, 30), it.next());
	}
@Test
    public void testRemove8() {
		list.addRange(Integer.MIN_VALUE, Integer.MIN_VALUE+5);
		list.addRange(-466, -460);
		list.addRange(-12, -11);
		list.addRange(-10, -5);
		list.addRange(0,2);
		list.addRange(6,8);
		list.addRange(9,11);
		list.addRange(12, 14);
		list.removeRange(1, 10);
		list.removeRange(Integer.MIN_VALUE+3, -8);
		assertEquals(5, list.getNumRanges());
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range(Integer.MIN_VALUE, Integer.MIN_VALUE+2), it.next());
		assertEquals(new Range(-7, -5), it.next());
		assertEquals(new Range(0, 0), it.next());
		assertEquals(new Range(11, 11), it.next());
		assertEquals(new Range(12, 14), it.next());
	}
		
@Test
    public void testContains() {
		list.addRange(4, 7);
		list.addRange(10,11);
		assertTrue(!list.contains(2));
		assertTrue(!list.contains(3));
		assertTrue(list.contains(4));
		assertTrue(list.contains(5));
		assertTrue(list.contains(6));
		assertTrue(list.contains(7));
		assertTrue(!list.contains(8));
		assertTrue(!list.contains(9));
		assertTrue(list.contains(10));
		assertTrue(list.contains(11));
		assertTrue(!list.contains(12));
		assertTrue(!list.contains(13));
	}
@Test
    public void testGetRangeIndex() {
		list.addRange(2,4);
		list.addRange(6,8);
		list.addRange(12,15);
		
		assertEquals(-1, list.getRangeIndex(0));
		assertEquals(-1, list.getRangeIndex(1));
		assertEquals(0, list.getRangeIndex(2));
		assertEquals(0, list.getRangeIndex(3));
		assertEquals(0, list.getRangeIndex(4));
		assertEquals(-2, list.getRangeIndex(5));
		assertEquals(1, list.getRangeIndex(6));
		assertEquals(1, list.getRangeIndex(7));
		assertEquals(1, list.getRangeIndex(8));
		assertEquals(-3, list.getRangeIndex(9));
		assertEquals(-3, list.getRangeIndex(10));
		assertEquals(-3, list.getRangeIndex(11));
		assertEquals(2, list.getRangeIndex(12));
		assertEquals(2, list.getRangeIndex(13));
		assertEquals(2, list.getRangeIndex(14));
		assertEquals(2, list.getRangeIndex(15));
		assertEquals(-4, list.getRangeIndex(16));
		assertEquals(-4, list.getRangeIndex(17));

	}
@Test
    public void testGetRange() {
		list.addRange(-231, -111);
		list.addRange(-120, -109);
		list.addRange(-108, -105);
		list.addRange(2, 4);
		list.addRange(6, 8);
		list.addRange(9, 11);
		list.addRange(12, 15);
		assertEquals(new Range(-231, -109), list.getRange(0));
		assertEquals(new Range(-108, -105), list.getRange(1));
		assertEquals(new Range(2, 4), list.getRange(2));
		assertEquals(new Range(6, 8), list.getRange(3));
		assertEquals(new Range(9, 11), list.getRange(4));
		assertEquals(new Range(12, 15), list.getRange(5));
		assertEquals(null, list.getRange(6));
	}
@Test
    public void testIterator() {
		list.addRange(Integer.MIN_VALUE, Integer.MIN_VALUE+1);
		list.addRange(-1234,-1231);
		list.addRange(-13, -9);
		list.addRange(-8, -7);
		list.addRange(-1, 1);
		list.addRange(3,4);
		list.addRange(5,5);
		list.addRange(6,8);
		list.addRange(12,15);
		list.addRange(Integer.MAX_VALUE-3, Integer.MAX_VALUE);
		Iterator<Range> it = list.getRanges();
		assertEquals(new Range(Integer.MIN_VALUE, Integer.MIN_VALUE+1), it.next());
		assertEquals(new Range(-1234,-1231), it.next());
		assertEquals(new Range(-13, -9), it.next());
		assertEquals(new Range(-8, -7), it.next());
		assertEquals(new Range(-1, 1), it.next());
		assertEquals(new Range(3,4), it.next());
		assertEquals(new Range(5,5), it.next());
		assertEquals(new Range(6,8), it.next());
		assertEquals(new Range(12,15), it.next());
		assertEquals(new Range(Integer.MAX_VALUE-3, Integer.MAX_VALUE), it.next());

		it = list.getRanges(false);
		assertEquals(new Range(Integer.MAX_VALUE-3, Integer.MAX_VALUE), it.next());
		assertEquals(new Range(12,15), it.next());
		assertEquals(new Range(6,8), it.next());
		assertEquals(new Range(5,5), it.next());
		assertEquals(new Range(3,4), it.next());
		assertEquals(new Range(-1, 1), it.next());
		assertEquals(new Range(-8, -7), it.next());
		assertEquals(new Range(-13, -9), it.next());
		assertEquals(new Range(-1234,-1231), it.next());
		assertEquals(new Range(Integer.MIN_VALUE, Integer.MIN_VALUE+1), it.next());
	}
@Test
    public void testSize() {
		list.addRange(Integer.MIN_VALUE, Integer.MIN_VALUE+1);
		list.addRange(-1234,-1231);
		list.addRange(-13, -9);
		list.addRange(-8, -6);
		list.addRange(-1, 1);
		list.addRange(3, 4);
		list.addRange(6, 8);
		list.addRange(12, 15);
		list.addRange(16, 19);
		list.addRange(Integer.MAX_VALUE-1, Integer.MAX_VALUE);
		assertEquals(32, list.getNumValues());
	}
@Test
    public void testIntersects() {
		list.addRange(10,19);
		list.addRange(40,49);
		list.addRange(60,69);
		assertTrue(!list.intersects(0,5));
		assertTrue(!list.intersects(0,9));
		assertTrue(!list.intersects(20,39));
		assertTrue(!list.intersects(50,55));
		assertTrue(!list.intersects(50,59));
		assertTrue(!list.intersects(70,80));
		assertTrue(!list.intersects(100,200));

		assertTrue(list.intersects(0,10));
		assertTrue(list.intersects(0,11));
		assertTrue(list.intersects(0,19));
		assertTrue(list.intersects(0,20));
		assertTrue(list.intersects(0,21));
		assertTrue(list.intersects(0,45));
		assertTrue(list.intersects(0, 100));

		assertTrue(list.intersects(9,10));
		assertTrue(list.intersects(9,11));
		assertTrue(list.intersects(9,19));
		assertTrue(list.intersects(9,20));
		assertTrue(list.intersects(9,21));
		assertTrue(list.intersects(9,40));
		assertTrue(list.intersects(9,100));

		assertTrue(list.intersects(10,10));
		assertTrue(list.intersects(10,11));
		assertTrue(list.intersects(10,19));
		assertTrue(list.intersects(10,20));
		assertTrue(list.intersects(10,21));
		assertTrue(list.intersects(10,40));
		assertTrue(list.intersects(10,100));

		assertTrue(list.intersects(11,11));
		assertTrue(list.intersects(11,19));
		assertTrue(list.intersects(11,20));
		assertTrue(list.intersects(11,21));
		assertTrue(list.intersects(11,40));
		assertTrue(list.intersects(11,100));

		assertTrue(list.intersects(15,16));
		assertTrue(list.intersects(15,19));
		assertTrue(list.intersects(15,20));
		assertTrue(list.intersects(15,21));
		assertTrue(list.intersects(15,40));
		assertTrue(list.intersects(15,100));

	}
@Test
    public void testIntersect() {
		list.addRange(10,19);
		list.addRange(40,49);
		list.addRange(60,69);
		AdjacentSortedRangeList other = new AdjacentSortedRangeList();
		other.addRange(5,15);
		other.addRange(38, 52);
		other.addRange(62,65);
		AdjacentSortedRangeList intersection = list.intersect(other);
		Iterator<Range> it = intersection.getRanges();
		assertEquals(new Range(10,15), it.next());
		assertEquals(new Range(40, 49), it.next());
		assertEquals(new Range(62, 65), it.next());
		
	}
@Test
    public void testIntersect2() {
		list.addRange(10,19);
		list.addRange(20,25);
		list.addRange(40,49);
		list.addRange(60,69);
		AdjacentSortedRangeList other = new AdjacentSortedRangeList();
		other.addRange(5,15);
		other.addRange(19,22);
		other.addRange(38,52);
		other.addRange(62,65);
		other.addRange(66,67);
		AdjacentSortedRangeList intersection = list.intersect(other);
		Iterator<Range> it = intersection.getRanges();
		assertEquals(new Range(10, 15), it.next());
		assertEquals(new Range(19, 19), it.next());
		assertEquals(new Range(20, 22), it.next());
		assertEquals(new Range(40, 49), it.next());
		assertEquals(new Range(62, 65), it.next());
		assertEquals(new Range(66, 67), it.next());
		
	}
@Test
    public void testIntersectPosAndNeg() {
		list.addRange(-555666777, -555444333);
		list.addRange(-555444332, -555444329);
		list.addRange(-888997890, -888111222);
		list.addRange(Integer.MIN_VALUE, -2142002000);
		list.addRange(-987, 234);
		list.addRange(500, 1500);
		list.addRange(654321, Integer.MAX_VALUE);
		AdjacentSortedRangeList other = new AdjacentSortedRangeList();
		other.addRange(-5,15);
		other.addRange(38, 48);
		other.addRange(49, 52);
		other.addRange(300, 600);
		other.addRange(-123456789, -111222333);
		other.addRange(-555777000, -555444888);
		other.addRange(-555444555, -555444222);
		other.addRange(-2143002000, -2142001000);
		AdjacentSortedRangeList intersection = list.intersect(other);
		Iterator<Range> it = intersection.getRanges();
		assertEquals(new Range(-2143002000, -2142002000), it.next());
		assertEquals(new Range(-555666777, -555444888), it.next());
		assertEquals(new Range(-555444555, -555444333), it.next());
		assertEquals(new Range(-555444332, -555444329), it.next());
		assertEquals(new Range(-5,15), it.next());
		assertEquals(new Range(38, 48), it.next());
		assertEquals(new Range(49, 52), it.next());
		assertEquals(new Range(500, 600), it.next());
	}

}
