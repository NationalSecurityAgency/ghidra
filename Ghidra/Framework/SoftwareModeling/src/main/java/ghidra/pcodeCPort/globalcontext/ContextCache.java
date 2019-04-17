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
package ghidra.pcodeCPort.globalcontext;

import ghidra.pcodeCPort.address.*;
import ghidra.pcodeCPort.space.*;
import ghidra.pcodeCPort.utils.*;

public class ContextCache {

    private ContextDatabase database = null;
    private boolean allowset;
    private AddrSpace curspace = null;
    private long first;
    private long last;
    private int[] context; // Cached context

    public void allowSet( boolean val ) {
        allowset = val;
    }

    public ContextCache( ContextDatabase db ) {
        database = db;
        curspace = null; // Mark cache as invalid
        allowset = true;
    }

    public void dispose() {
    }

    public ContextDatabase getDatabase() {
        return database;
    }

    public void getContext( Address addr, int[] buf ) {
        if ( (!addr.getSpace().equals( curspace ))
            || (Utils.unsignedCompare( first, addr.getOffset() ) > 0)
            || (Utils.unsignedCompare( last, addr.getOffset() ) < 0) ) {
            curspace = addr.getSpace();

            MutableLong firstMutable = new MutableLong( first );
            MutableLong lastMutable = new MutableLong( last );
            context = database.getContext( addr, firstMutable, lastMutable );

            first = firstMutable.get();
            last = lastMutable.get();
        }
        for ( int i = 0; i < database.getContextSize(); ++i ) {
            buf[i] = context[i];
        }
    }

    public void setContext( Address addr, int num, int mask, int value ) {
        if ( !allowset ) {
            return;
        }
        database.setContextRange( addr, num, mask, value );
        if ( (addr.getSpace().equals( curspace ))
            && (Utils.unsignedCompare( first, addr.getOffset() ) <= 0)
            && (Utils.unsignedCompare( last, addr.getOffset() ) >= 0) ) {
            curspace = null; // Invalidate cache
        }
    }

}
