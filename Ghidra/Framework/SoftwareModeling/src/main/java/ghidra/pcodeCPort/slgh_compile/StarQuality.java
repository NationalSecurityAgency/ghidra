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

import ghidra.pcodeCPort.semantics.*;
import ghidra.sleigh.grammar.Location;

public class StarQuality {
    public final Location location;

    private ConstTpl id;
    private int size;

    public StarQuality(Location location) {
        this.location = location;
        this.id = null;
        this.size = 0;
    }
    
    // don't need these complicated constructors right now
//    public StarQuality(ConstTpl id, int size) {
//        this.id = new ConstTpl(id);
//        this.size = size;
//    }
//
//    public StarQuality(StarQuality sq) {
//        this.id = new ConstTpl(sq.id);
//        this.size = sq.size;
//    }

    public ConstTpl getId() {
        return id;
    }

    public void setId(ConstTpl id) {
//        this.id = new ConstTpl(id);
        // currently no need to copy because all uses of this in
        // SleighCompiler are on new instances anyway
        this.id = id;
    }

    public int getSize() {
        return size;
    }

    public void setSize(int size) {
        this.size = size;
    }
}
