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
package generic.stl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class VectorSTLTest extends AbstractGenericTest {

	public VectorSTLTest() {
		super();
	}

	@Test
	public void testLowerBound() {
		VectorSTL<Integer> v = new VectorSTL<Integer>();
		v.push_back(3);
		v.push_back(4);
		v.push_back(4);
		v.push_back(4);
		v.push_back(7);
		v.push_back(9);

		assertEquals(3, (int) v.lower_bound(2).get());
		assertEquals(4, (int) v.lower_bound(4).get());
		assertEquals(4, (int) v.lower_bound(4).increment().get());
		assertEquals(4, (int) v.lower_bound(4).increment().increment().get());

		assertTrue(v.lower_bound(10).isEnd());

	}

	@Test
	public void testUpperBound() {
		VectorSTL<Integer> v = new VectorSTL<Integer>();
		v.push_back(3);
		v.push_back(4);
		v.push_back(4);
		v.push_back(4);
		v.push_back(7);
		v.push_back(9);

		assertEquals(3, (int) v.upper_bound(2).get());
		assertEquals(7, (int) v.upper_bound(4).get());
		assertEquals(4, (int) v.upper_bound(4).decrement().get());
		assertEquals(4, (int) v.upper_bound(4).decrement().decrement().get());

		assertTrue(v.upper_bound(10).isEnd());

	}

	@Test
	public void testMerge() {
		VectorSTL<Integer> v1 = new VectorSTL<Integer>();
		v1.push_back(3);
		v1.push_back(4);
		v1.push_back(4);
		v1.push_back(4);
		v1.push_back(7);
		v1.push_back(9);

		VectorSTL<Integer> v2 = new VectorSTL<Integer>();
		v2.push_back(1);
		v2.push_back(2);
		v2.push_back(4);
		v2.push_back(6);
		v2.push_back(7);
		v2.push_back(10);

		VectorSTL<Integer> destination = new VectorSTL<Integer>();
		VectorSTL.merge(v1, v2, destination);

		assertEquals(12, destination.size());
		assertEquals(1, (int) destination.get(0));
		assertEquals(2, (int) destination.get(1));
		assertEquals(3, (int) destination.get(2));
		assertEquals(4, (int) destination.get(3));
		assertEquals(4, (int) destination.get(4));
		assertEquals(4, (int) destination.get(5));
		assertEquals(4, (int) destination.get(6));
		assertEquals(6, (int) destination.get(7));
		assertEquals(7, (int) destination.get(8));
		assertEquals(7, (int) destination.get(9));
		assertEquals(9, (int) destination.get(10));
		assertEquals(10, (int) destination.get(11));

	}

	@Test
	public void testInsert() {
		VectorSTL<Integer> v1 = new VectorSTL<Integer>();
		v1.push_back(3);
		v1.push_back(4);
		v1.push_back(5);
		v1.push_back(6);
		v1.push_back(7);
		v1.push_back(9);

		VectorSTL<Integer> v2 = new VectorSTL<Integer>();
		v2.push_back(1);
		v2.push_back(2);
		v2.push_back(8);
		v2.push_back(10);

		v1.insert(0, 0);
		assertEquals(0, (int) v1.get(0));

		v1.insertAll(v1.end(), v2);

		assertEquals(11, v1.size());
		assertEquals(0, (int) v1.get(0));
		assertEquals(3, (int) v1.get(1));
		assertEquals(4, (int) v1.get(2));
		assertEquals(5, (int) v1.get(3));
		assertEquals(6, (int) v1.get(4));
		assertEquals(7, (int) v1.get(5));
		assertEquals(9, (int) v1.get(6));
		assertEquals(1, (int) v1.get(7));
		assertEquals(2, (int) v1.get(8));
		assertEquals(8, (int) v1.get(9));
		assertEquals(10, (int) v1.get(10));

		v1.insert(10, 11);
		assertEquals(10, (int) v1.get(11));

		VectorSTL<Integer> v3 = new VectorSTL<Integer>();
		v3.push_back(31);
		v3.push_back(32);
		v3.push_back(33);

		IteratorSTL<Integer> iter = v2.begin();
		iter.increment();
		v2.insertAll(iter, v3);

		assertEquals(7, v2.size());
		assertEquals(1, (int) v2.get(0));
		assertEquals(31, (int) v2.get(1));
		assertEquals(32, (int) v2.get(2));
		assertEquals(33, (int) v2.get(3));
		assertEquals(2, (int) v2.get(4));
		assertEquals(8, (int) v2.get(5));
		assertEquals(10, (int) v2.get(6));
	}

	@Test
	public void testAssign() {
		VectorSTL<Integer> a = new VectorSTL<Integer>();
		VectorSTL<Integer> b = new VectorSTL<Integer>();

		a.push_back(1);
		a.push_back(2);
		b.assign(a);
		assertEquals(2, b.size());

	}
//	public void testFloat() {
//		double x = -4500;
//		long bits = Double.doubleToRawLongBits( x );
//		int s = ((bits >> 63) == 0) ? 1 : -1;
//		int e = (int)((bits >> 52) & 0x7ffL);
//		long m = (e == 0) ?
//                 (bits & 0xfffffffffffffL) << 1 :
//                 (bits & 0xfffffffffffffL) | 0x10000000000000L;
//		m <<= 11;
//		e = e - 1023;
//		
//		System.out.println("s = "+s);
//		System.out.println("m = "+Long.toHexString( m ));
//		System.out.println("e = "+e);
//	}
}
