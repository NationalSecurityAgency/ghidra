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
package ghidra.app.util.opinion;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class QueryOpinionServiceTest {

	@Test
	public void testSecondaryAttributeMatches() {

		/*
			Values taken from MIPS.opinion
			
			00110000111100000011000100001111
			00010000000011110001010000000000
			00000000101001010001000100000101
		*/

		String flags = "111";
		String attribute = "0b 00.. ..00 .... .... 00.1 0.0. 0000 ....";
		assertFalse(QueryOpinionService.secondaryAttributeMatches(flags, attribute));

		flags = "821047567";
		assertTrue(QueryOpinionService.secondaryAttributeMatches(flags, attribute));

		assertTrue(QueryOpinionService.secondaryAttributeMatches(flags, attribute));

		flags = "269423616";
		assertTrue(QueryOpinionService.secondaryAttributeMatches(flags, attribute));

		flags = "10817797";
		assertTrue(QueryOpinionService.secondaryAttributeMatches(flags, attribute));

	}

}
