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
package ghidra.util.xml;

class XmlSummary {

    static String getSummary(Counter counter) {
        StringBuffer buffer = new StringBuffer(256);

		int origTotal = counter.getTotalCount();

        buffer.append("\n");
        buffer.append("\n"+"XML Program Summary:");
        buffer.append("\n"+"--------------------------");
        buffer.append("\n"+"Memory Sections:       " + counter.getCountAndRemove("MEMORY_SECTION"));
        buffer.append("\n"+"Memory Contents:       " + counter.getCountAndRemove("MEMORY_CONTENTS"));
        buffer.append("\n"+"Code Blocks:           " + counter.getCountAndRemove("CODE_BLOCK"));
        buffer.append("\n"+"Defined Data:          " + counter.getCountAndRemove("DEFINED_DATA"));
        buffer.append("\n"+"Structures:            " + counter.getCountAndRemove("STRUCTURE"));
        buffer.append("\n"+"Unions:                " + counter.getCountAndRemove("UNION"));
        buffer.append("\n"+"Typedefs:              " + counter.getCountAndRemove("TYPE_DEF"));
        buffer.append("\n"+"Enums:                 " + counter.getCountAndRemove("ENUM"));
        buffer.append("\n"+"Symbols:               " + counter.getCountAndRemove("SYMBOL"));
        buffer.append("\n"+"Entry Points:          " + counter.getCountAndRemove("PROGRAM_ENTRY_POINT"));
        buffer.append("\n"+"Equates:               " + counter.getCountAndRemove("EQUATE"));
        buffer.append("\n"+"    References:        " + counter.getCountAndRemove("EQUATE_REFERENCE"));
        buffer.append("\n"+"Comments:              " + counter.getCountAndRemove("COMMENT"));
		buffer.append("\n"+"Bookmarks:             " + counter.getCountAndRemove("BOOKMARK"));
        buffer.append("\n"+"Properties:            " + counter.getCountAndRemove("PROPERTY"));
        buffer.append("\n"+"Program Trees:         " + counter.getCountAndRemove("TREE"));
        buffer.append("\n"+"    Folders:           " + counter.getCountAndRemove("FOLDER"));
        buffer.append("\n"+"    Fragments:         " + counter.getCountAndRemove("FRAGMENT"));
		buffer.append("\n"+"Function Signatures:   " + counter.getCountAndRemove("FUNCTION_DEF"));
		buffer.append("\n"+"    Parameters:        " + counter.getCountAndRemove("PARAMETER"));
        buffer.append("\n"+"Functions:             " + counter.getCountAndRemove("FUNCTION"));
        buffer.append("\n"+"    Stack Frames:      " + counter.getCountAndRemove("STACK_FRAME"));
        buffer.append("\n"+"    Stack Vars:        " + counter.getCountAndRemove("STACK_VAR"));
        buffer.append("\n"+"    Register Vars:     " + counter.getCountAndRemove("REGISTER_VAR"));
        buffer.append("\n"+"References:            " + counter.getCountAndRemove("MEMORY_REFERENCE")
                                                     + counter.getCountAndRemove("STACK_REFERENCE")
                                                     + counter.getCountAndRemove("EXT_LIBRARY_REFERENCE"));
        buffer.append("\n"+"Relocations:           " + counter.getCountAndRemove("RELOCATION"));
		buffer.append("\n");

		counter.getCountAndRemove("MEMBER");//remove from overhead...

		buffer.append("\n"+"--------------------------");
		buffer.append("\n"+"Total XML Elements:    " + origTotal);
		buffer.append("\n"+"    Processed:         " + (origTotal-counter.getTotalCount()));
		buffer.append("\n"+"    Overhead:          " + counter.getTotalCount());
        buffer.append("\n");

		counter.clear();

        return buffer.toString();
    }

}
