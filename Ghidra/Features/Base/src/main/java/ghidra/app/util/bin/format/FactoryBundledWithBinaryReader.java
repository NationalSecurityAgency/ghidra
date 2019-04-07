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
package ghidra.app.util.bin.format;

import generic.continues.*;
import ghidra.app.util.bin.*;

public class FactoryBundledWithBinaryReader extends BinaryReader {
    private final GenericFactory factory;

    public GenericFactory getFactory() {
        return factory;
    }

    public FactoryBundledWithBinaryReader(GenericFactory factory,
            ByteProvider provider, boolean isLittleEndian) {
        super(provider, isLittleEndian);
        if (factory == null) {
            throw new IllegalArgumentException("factory == null not allowed");
        }
        this.factory = factory;
    }
}
