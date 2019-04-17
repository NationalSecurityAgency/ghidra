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
 * This class represents a signed encoded number (following wiki page naming convention for
 * Microsoft Demangler) within a Microsoft mangled symbol.
 */
public class MDSignedEncodedNumber extends MDEncodedNumber {

	boolean signed = false;

	public MDSignedEncodedNumber(MDMang dmang) {
		super(dmang);
	}

	@Override
	public BigInteger getValue() {
		if (signed) {
			return value.negate();
		}
		return value;
	}

	@Override
	public void setValue(BigInteger value) {
		if (value.signum() == -1) {
			this.value = value.negate();
			signed = true;
		}
		else {
			this.value = value;
			signed = false;
		}
	}

	@Override
	public void insert(StringBuilder builder) {
		super.insert(builder);
		if (signed) {
			dmang.insertString(builder, "-");
		}
	}

	@Override
	protected void parseInternal() throws MDException {
		if (dmang.peek() == '?') {
			signed = true;
			dmang.increment();
		}
		super.parseInternal();
		// The following block of code is good, except for when MSFT allows "?0" to
		// represent "-0"instead of zero. Therefore, we are commenting this out for
		// "signed" a member instead of local variable, and overriding the following
		// now, making methods: insert, getValue, and setValue.
		// if (signed) {
		// value = value.negate();
		// }
	}
}

/******************************************************************************/
/******************************************************************************/
