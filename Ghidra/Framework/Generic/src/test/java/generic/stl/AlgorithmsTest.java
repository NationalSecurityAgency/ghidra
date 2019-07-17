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

import org.junit.Test;

import generic.test.AbstractGenericTest;


public class AlgorithmsTest extends AbstractGenericTest {

	public AlgorithmsTest() {
		super();
	}
@Test
    public void testLowerBoundAndUpperBound() {
		VectorSTL<Integer> a = new VectorSTL<Integer>();
		a.push_back( 1 );
		a.push_back( 2 );
		a.push_back( 3 );
		a.push_back( 3 );
		a.push_back( 4 );
		a.push_back( 5 );
		
		IteratorSTL<Integer> iter = Algorithms.lower_bound( a.begin(), a.end(), 3 );
		assertEquals(3, (int)iter.get());
		iter.increment();
		assertEquals(3, (int)iter.get());
		
		iter = Algorithms.upper_bound( a.begin(), a.end(), 3 );
		assertEquals(4, (int)iter.get());
		
	}
}
