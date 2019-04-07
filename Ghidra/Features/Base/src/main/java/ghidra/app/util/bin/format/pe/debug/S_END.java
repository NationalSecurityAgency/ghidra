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
package ghidra.app.util.bin.format.pe.debug;

import ghidra.app.util.bin.format.*;
import ghidra.util.*;

/**
 * 
 */
class S_END extends DebugSymbol {

	static S_END createS_END(short length, short type,
            FactoryBundledWithBinaryReader reader, int ptr) {
	    S_END s_end = (S_END) reader.getFactory().create(S_END.class);
	    s_end.initS_END(length, type, reader, ptr);
	    return s_end;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public S_END() {}

    private void initS_END(short length, short type, FactoryBundledWithBinaryReader reader, int ptr) {
		processDebugSymbol(length, type);
		Msg.debug(this, reader.getPointerIndex()+" -- "+ptr);
		this.name = "END";
		this.offset = 0;
		this.section = 0;		
	}
}
