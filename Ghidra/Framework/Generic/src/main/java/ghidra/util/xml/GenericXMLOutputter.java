/* ###
 * IP: GHIDRA
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
package ghidra.util.xml;

import org.jdom.output.Format;
import org.jdom.output.XMLOutputter;
import org.jdom.output.Format.TextMode;

/**
 * A simple extension of <code>XMLOutputter</code> that sets default settings to fix common bugs.
 */
public class GenericXMLOutputter extends XMLOutputter {

    public static final String DEFAULT_INDENT = "    ";
    
    /**
     * This constructor performs basic setup that can be changed later by the user.  For example,
     * <pre>
     *      setTextNormalize( true );
     *      setIndent( DEFAULT_INDENT );
     *      setNewlines( true );
     * </pre>
     */
    public GenericXMLOutputter() {
        init();
    }
    
    private void init() {
        // this prevents an excess build up of whitespace
        Format compactFormat = Format.getCompactFormat();
        compactFormat.setIndent( DEFAULT_INDENT );
        compactFormat.setTextMode( TextMode.NORMALIZE );
        setFormat( compactFormat );
    }
}
