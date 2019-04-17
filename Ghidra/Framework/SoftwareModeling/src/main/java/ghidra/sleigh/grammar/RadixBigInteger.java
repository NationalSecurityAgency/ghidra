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
package ghidra.sleigh.grammar;

import java.math.BigInteger;
import java.util.Random;

public class RadixBigInteger extends BigInteger {
    private static final long serialVersionUID = -7927157989937732244L;
    protected int preferredRadix = 10;
    public final Location location;

    public RadixBigInteger(Location location, byte[] val) {
        super(val);
        this.location = location;
    }

    public RadixBigInteger(Location location, String val) {
        super(val);
        this.location = location;
    }

    public RadixBigInteger(Location location, int signum, byte[] magnitude) {
        super(signum, magnitude);
        this.location = location;
    }

    public RadixBigInteger(Location location, String val, int radix) {
        super(val, radix);
        preferredRadix = radix;
        this.location = location;
    }

    public RadixBigInteger(Location location, int numBits, Random rnd) {
        super(numBits, rnd);
        this.location = location;
    }

    public RadixBigInteger(Location location, int bitLength, int certainty, Random rnd) {
        super(bitLength, certainty, rnd);
        this.location = location;
    }

    public int getPreferredRadix() {
        return preferredRadix;
    }

    public void setPreferredRadix(int preferredRadix) {
        this.preferredRadix = preferredRadix;
    }

    @Override
    public String toString() {
        String s = super.toString(preferredRadix);
        if (preferredRadix == 16) {
            s = "0x" + s;
        }
        return s;
    }
}
