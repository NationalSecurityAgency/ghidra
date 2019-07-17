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

// Qualities of an address space
public class SpaceQuality {
    public String name;
    public space_class type;
    public int size;
    public int wordsize; // number of bytes in unit of the space
    public boolean isdefault;

    // Default space qualities
    public SpaceQuality(String nm) {
        name = nm;
        type = space_class.ram_space;
        size = 0;
        wordsize = 1;
        isdefault = false;
    }
    @Override
    public String toString() {
        return "sq:{" + name + "," + type + "," + size + "," + wordsize + "," + isdefault + "}";
    }
}
