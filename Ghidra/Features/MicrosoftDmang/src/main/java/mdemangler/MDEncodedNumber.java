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
package mdemangler;

import java.math.BigInteger;

/**
 * This class represents an encoded number (following wiki page naming convention for
 * Microsoft Demangler) within a Microsoft mangled symbol.
 */
public class MDEncodedNumber extends MDParsableItem {
	String number = "";
	BigInteger value;

	public MDEncodedNumber(MDMang dmang) {
		super(dmang);
	}

	public BigInteger getValue() {
		return value;
	}

	public void setValue(BigInteger value) {
		this.value = value;
	}

	@Override
	public void insert(StringBuilder builder) {
		dmang.insertSpacedString(builder, value.toString());
	}

// ORIGINAL IMPLEMENTATION	
//	@Override
//	protected void parseInternal(MDMang dmang) throws MDMangException {
//		if (dmang.peek() >= '0' && dmang.peek() <= '9') {
//			value = BigInteger.valueOf(dmang.getAndIncrement() - '0' + 1);
//		}
//		else if (dmang.peek() >= 'A' && dmang.peek() <= 'P' || dmang.peek() == '@') {
//			// 20170331: Discovered from encoded number ("?IAAAAAAAAAAAAAAA" which our code
//			// had returned "--9223372036854775808") that Java fails us with not having an
//			// unsigned long data type.  If I add an 'A' to the sequence, MSFT returns "-0"
//			// which is because it is doing left shifts, which have rolled the '1' bit off
//			// the left, but if I try "?IAAAAAAAAAAAAAAB" MSFT reports"-9223372036854775809"
//			// meaning that MSFT is very likely using a 64-bit unsigned long.  So decided to
//			// go with Java "BigInteger" for now, even though it will allow numbers bigger
//			// than a 64-bit unsigned long.  I could add the logic to truncate those, but
//			// we should not see those unless MSFT produces those, which should mean that
//			// numbers larger than 64 bits are then the norm.
//			value = new BigInteger("0");
//			char ch;
//			while ((ch = dmang.getAndIncrement()) != '@') {
//				if (ch < 'A' || ch > 'P') {
//					throw new MDMangException("Invalid Encoded Number");
//				}
//				value = value.shiftLeft(4);
//				value = value.add(BigInteger.valueOf(ch - 'A'));
//			}
//		}
//		else {
//			throw new MDMangException("Invalid Encoded Number");
//		}
//	}
//
	@Override
	protected void parseInternal() throws MDException {
		if (dmang.peek() >= '0' && dmang.peek() <= '9') {
			value = BigInteger.valueOf(dmang.getAndIncrement() - '0' + 1);
		}
		else if (dmang.peek() >= 'A' && dmang.peek() <= 'P' || dmang.peek() == '@') {
			// 20170331: Discovered from encoded number ("?IAAAAAAAAAAAAAAA" which our code
			// had returned "--9223372036854775808") that Java fails us with not having an
			// unsigned long data type.  If I add an 'A' to the sequence, MSFT returns "-0"
			// which is because it is doing left shifts, which have rolled the '1' bit off
			// the left, but if I try "?IAAAAAAAAAAAAAAB" MSFT reports"-9223372036854775809"
			// meaning that MSFT is very likely using a 64-bit unsigned long.  So decided to
			// go with Java "BigInteger" for now, even though it will allow numbers bigger
			// than a 64-bit unsigned long.  I could add the logic to truncate those, but
			// we should not see those unless MSFT produces those, which should mean that
			// numbers larger than 64 bits are then the norm.
			value = new BigInteger("0");
			while ((dmang.peek() >= 'A') && (dmang.peek() <= 'P')) {
				value = value.shiftLeft(4);
				value = value.add(BigInteger.valueOf(dmang.getAndIncrement() - 'A'));
			}
			if (dmang.peek() == '@') {
				dmang.increment();
			}
		}
		else {
			throw new MDException("Illegal character in MDEncodedNumber: " + dmang.peek());
		}
	}
}

/******************************************************************************/
/******************************************************************************/
