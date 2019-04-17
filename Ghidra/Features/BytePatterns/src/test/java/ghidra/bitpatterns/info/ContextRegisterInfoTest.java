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

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class ContextRegisterInfoTest extends AbstractGenericTest {

	@Test
	public void testEquals() {
		BigInteger one = new BigInteger("1");
		BigInteger three = new BigInteger("3");

		String cReg1 = "contextRegister1";
		String cReg2 = "contextRegister2";

		ContextRegisterInfo info1 = new ContextRegisterInfo(cReg1);
		ContextRegisterInfo info2 = new ContextRegisterInfo(cReg1);
		ContextRegisterInfo info3 = new ContextRegisterInfo(cReg2);

		//test comparison with null
		Assert.assertNotEquals(null, info1);

		//test comparison with object of wrong class
		Assert.assertNotEquals(this, info1);

		//test registers with no values set
		assertEquals(info1, info1);
		assertEquals(info1, info2);
		assertEquals(info2, info1);
		Assert.assertNotEquals(info1, info3);
		Assert.assertNotEquals(info3, info1);

		info1.setValue(one);
		info2.setValue(one);
		info3.setValue(three);

		assertEquals(info1, info1);
		assertEquals(info1, info2);
		assertEquals(info2, info1);
		Assert.assertNotEquals(info1, info3);
		Assert.assertNotEquals(info3, info1);
	}

}
