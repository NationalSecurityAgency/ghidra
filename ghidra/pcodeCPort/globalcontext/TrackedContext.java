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
import ghidra.pcodeCPort.pcoderaw.*;
import ghidra.pcodeCPort.translate.*;
import ghidra.pcodeCPort.utils.*;

import java.io.PrintStream;

import org.jdom.Element;



public class TrackedContext {
    public VarnodeData loc = new VarnodeData();
    public long val;

    public void saveXml( PrintStream s ) {
        s.append( "<set" );
        loc.space.saveXmlAttributes( s, loc.offset, loc.size );
        XmlUtils.a_v_u( s, "val", val );
        s.append( "/>\n" );
    }

    public void restoreXml( Element el, Translate trans ) {
        VarnodeData varnodeData = Address.restoreXml( el, trans );
        Address addr = varnodeData.getAddress();
        int size = varnodeData.size;

        val = XmlUtils.decodeUnknownLong( el.getAttributeValue( "val" ) );

        loc.space = addr.getSpace();
        loc.offset = addr.getOffset();
        loc.size = size;
    }
}
