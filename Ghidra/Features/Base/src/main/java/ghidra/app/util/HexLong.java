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
package ghidra.app.util;

public class HexLong extends Number {
    public final Long longValue;

    public HexLong(long longValue) {
        this.longValue = longValue;
    }

    @Override
    public double doubleValue() {
        return longValue.doubleValue();
    }

    @Override
    public float floatValue() {
        return longValue.floatValue();
    }

    @Override
    public int intValue() {
        return longValue.intValue();
    }

    @Override
    public long longValue() {
        return longValue.longValue();
    }

    @Override
    public String toString() {
        return "0x" + Long.toHexString(longValue());
    }
}
