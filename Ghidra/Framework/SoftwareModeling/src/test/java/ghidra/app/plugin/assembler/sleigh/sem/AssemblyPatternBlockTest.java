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
package ghidra.app.plugin.assembler.sleigh.sem;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;

public class AssemblyPatternBlockTest {
	@Test
	public void testBitShiftRightByteArray() {
		assertArrayEquals(new byte[] { 1, 1, 1, 1 },
			AssemblyPatternBlock.bitShiftRightByteArray(new byte[] { 2, 2, 2, 2 }, 1));
		assertArrayEquals(new byte[] { 1, 7, (byte) 0x81, 1 },
			AssemblyPatternBlock.bitShiftRightByteArray(new byte[] { 2, 0xf, 2, 2 }, 1));
	}
}
