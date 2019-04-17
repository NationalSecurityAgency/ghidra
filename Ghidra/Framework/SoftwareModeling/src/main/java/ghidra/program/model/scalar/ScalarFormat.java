/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.scalar;

/**
 * ScalarFormat.java
 *
 * This class exists just to make it easy to hold onto sensible
 * groupings and conventions for formatting scalars.  This is
 * used by Scalar in the toString(ScalarFormat) and the 
 * addToStringBuffer(StringBuffer, ScalarFormat) methods.
 *
 * @version 1999/02/04
 */

public class ScalarFormat  {
	private boolean zeroPadded;
	private boolean signed;
	private String pre;
	private String post;
	private int radix;
	
	// Constructors:

	/**
	 * <p>Create a default ScalarFormat.  (hex, zeropadded, unsigned
	 * no pre or post strings)</p>
	 */
	public ScalarFormat() {
		radix = 16;
		zeroPadded = true;
		signed = false;
		pre = "";
		post = "";
	}
	
	/**
	 * <p> Create a ScalarFormat with the given values.</p>
	 *
	 * @param radix       the radix to use (only 2,8,10 and 16 are valid)..
	 * @param zeroPadded  true if value should be 0 padded.
	 * @param signed      true if value should be treated as signed.
	 * @param pre         string to add after optional sign but before value.
	 * @param post        string to add at end of the value.
	 * @throws IllegalArgumentException if radix is not one of (2,8,10,16).
	 */
	public ScalarFormat(int radix, boolean zeroPadded, boolean signed,
						String pre, String post) {
		switch (radix) {
			case 2:
			case 8:
			case 10:
			case 16:
				break;
			default:
				throw new IllegalArgumentException("Invalid radix");
		}
		this.zeroPadded = zeroPadded;
		this.signed = signed;
		this.pre = pre;
		this.post = post;
		this.radix = radix;
	}

	/**
	 * <p>Returns whether value should be zero padded.</p>
	 *
	 * @return whether value should be zero padded.
	 */
	public boolean isZeroPadded() {
		return zeroPadded;
	}
	
	/**
	 * <p>Returns whether value should be treated as signed.</p>
	 *
	 * @return whether value should be treated as signed.
	 */
	public boolean isSigned() {
		return signed;
	}
	
	/**
	 * <p>Returns the prefix string.</p>
	 *
	 * @return the prefix string.
	 */
	public String getPre() {
		return pre;
	}

	/**
	 * <p>Returns the postfix string.</p>
	 *
	 * @return the postfix string.
	 */
	public String getPost() {
		return post;
	}

	/**
	 * <p>Returns the radix.</p>
	 *
	 * @return the radix.
	 */
	public int getRadix() {
		return radix;
	}
	
	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
    public String toString() {
		StringBuffer buf = new StringBuffer();
		buf.append("(radix=" + radix + ", ");
		if (zeroPadded) {
			buf.append("zero padded, ");
		}
		if (signed) { 
			buf.append("signed, ");
		}
		buf.append("pre='" + pre + "', post='" + post + "')");
		return new String(buf);
	}
} // ScalarFormat
