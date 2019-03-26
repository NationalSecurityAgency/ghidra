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
package ghidra.bitpatterns.info;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.bitpatterns.info.PercentageFilter;

public class PercentageFilterTest extends AbstractGenericTest {

	@Test(expected = IllegalArgumentException.class)
	public void negativeTest() {
		@SuppressWarnings("unused")
		PercentageFilter pFilter = new PercentageFilter(-1.0);
	}

	@Test(expected = IllegalArgumentException.class)
	public void tooBigTest() {
		@SuppressWarnings("unused")
		PercentageFilter pFilter = new PercentageFilter(100.1);
	}

	public void basicTest() {
		PercentageFilter pFilter = new PercentageFilter(50.0);
		assertTrue(pFilter.allows(75.0));
		assertTrue(pFilter.allows(50.0));
		assertFalse(pFilter.allows(25.0));
	}

}
