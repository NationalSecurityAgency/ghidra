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
package ghidra.app.util.opinion;

import ghidra.program.model.lang.*;
import ghidra.util.datastruct.*;
import ghidra.xml.*;

public class QueryOpinionServiceHandler {
    private static class FullQuery {
        final String loader;
        final String primary;
        final String secondary;
        final LanguageCompilerSpecQuery query;

        FullQuery(String loader, String primary, String secondary,
                LanguageCompilerSpecQuery query) {
            this.loader = loader;
            this.primary = primary;
            this.secondary = secondary;
            this.query = query;
        }

        public FullQuery(FullQuery fullQuery, String loader, String primary,
                String secondary, LanguageCompilerSpecQuery query) {
            this.loader = (loader == null ? fullQuery.loader : loader);
            this.primary = (primary == null ? fullQuery.primary : primary);
            this.secondary = (secondary == null ? fullQuery.secondary
                    : secondary);
            this.query = new LanguageCompilerSpecQuery(query.processor == null ? fullQuery.query.processor
                    : query.processor, query.endian == null ? fullQuery.query.endian
                    : query.endian, query.size == null ? fullQuery.query.size
                    : query.size, query.variant == null ? fullQuery.query.variant
                    : query.variant, query.compilerSpecID == null ? fullQuery.query.compilerSpecID
                    : query.compilerSpecID

            );
        }
    }

    public static void read(XmlPullParser parser) {

        Stack<FullQuery> queryStack = new Stack<FullQuery>();
        queryStack.add(new FullQuery(null, null, null, new LanguageCompilerSpecQuery(null, null, null, null, null)));

        XmlElement root = parser.start("opinions");

        while (parser.peek().getName().equals("constraint")) {
        	XmlElement element = parser.next();

        	if (element.isStart()) {
	            FullQuery top = queryStack.peek();
	
	            String loader = element.getAttribute("loader");
	            String primary = element.getAttribute("primary");
	            String secondary = element.getAttribute("secondary");
	
	            String processorString = element.getAttribute("processor");
	            String endianString = element.getAttribute("endian");
	            String sizeString = element.getAttribute("size");
	            String variant = element.getAttribute("variant");
	            String compilerSpecIDString = element.getAttribute("compilerSpecID");
	
	            Processor processor = null;
	            if (processorString != null) {
	                processor = Processor.findOrPossiblyCreateProcessor(processorString);
	            }
	            Endian endian = null;
	            if (endianString != null) {
	                endian = Endian.toEndian(endianString);
	                if (endian == null) {
	                    throw new LoaderOpinionException("no such endian: "
	                            + endianString);
	                }
	            }
	            Integer size = null;
	            if (sizeString != null) {
	                try {
	                    size = Integer.parseInt(sizeString);
	                }
	                catch (NumberFormatException e) {
	                    throw new LoaderOpinionException("invalid size integer: "
	                            + sizeString, e);
	                }
	            }
	            CompilerSpecID compilerSpecID = null;
	            if (compilerSpecIDString != null) {
	                compilerSpecID = new CompilerSpecID(compilerSpecIDString);
	            }
	            FullQuery newFullQuery = new FullQuery(top, loader, primary, secondary, new LanguageCompilerSpecQuery(processor, endian, size, variant, compilerSpecID));
	            queryStack.push(newFullQuery);
	            QueryOpinionService.addQuery(newFullQuery.loader, newFullQuery.primary, newFullQuery.secondary, newFullQuery.query);
        	} else {
        		queryStack.pop();
        	}
        }
        parser.end(root);
    }
}
