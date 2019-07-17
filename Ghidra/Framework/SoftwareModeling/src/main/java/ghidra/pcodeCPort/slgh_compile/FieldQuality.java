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
package ghidra.pcodeCPort.slgh_compile;

import ghidra.sleigh.grammar.Location;

public class FieldQuality {
    public final Location location;
    public String name;
    public int low, high;
    public boolean signext;
    public boolean flow;
    public boolean hex;

    public FieldQuality(String nm, Location location, long l, long h) {
        name = nm;
        this.location = location;
        low = (int) l;
        high = (int) h;
        signext = false;
        flow = true;
        hex = true;
    }
    @Override
    public String toString() {
        return "fq:{" + name + "," + low + "," + high + "," + signext + "," + hex + "}";
    }
}
