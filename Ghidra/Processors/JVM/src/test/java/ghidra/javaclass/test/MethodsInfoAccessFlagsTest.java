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
package ghidra.javaclass.test;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.javaclass.flags.MethodsInfoAccessFlags;

public class MethodsInfoAccessFlagsTest {

	@Test
	public void testToString() {
		int flags = MethodsInfoAccessFlags.ACC_PUBLIC.getValue() |
			MethodsInfoAccessFlags.ACC_STATIC.getValue() |
			MethodsInfoAccessFlags.ACC_FINAL.getValue() |
			MethodsInfoAccessFlags.ACC_SYNCHRONIZED.getValue();
		String flagString = MethodsInfoAccessFlags.toString(flags);
		assertEquals("public static final synchronized", flagString);
		flags = MethodsInfoAccessFlags.ACC_PROTECTED.getValue() |
			MethodsInfoAccessFlags.ACC_NATIVE.getValue();
		assertEquals("protected native", MethodsInfoAccessFlags.toString(flags));
		flags = MethodsInfoAccessFlags.ACC_PRIVATE.getValue() |
			MethodsInfoAccessFlags.ACC_ABSTRACT.getValue();
		assertEquals("private abstract", MethodsInfoAccessFlags.toString(flags));
	}

}
