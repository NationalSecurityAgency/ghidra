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
package generic;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import generic.ULongSpan.DefaultULongSpanSet;
import generic.ULongSpan.MutableULongSpanSet;

public class ULongSpanTest {
	@Test
	public void testULongSpanSet() {
		MutableULongSpanSet set = new DefaultULongSpanSet();
		
		set.add(ULongSpan.extent(0, 50));
		set.add(ULongSpan.extent(50,50));
		
		assertEquals(ULongSpan.extent(0, 100), Unique.assertOne(set.spans()));
	}
}
