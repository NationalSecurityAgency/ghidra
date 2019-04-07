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
package ghidra.app.util.viewer.field;

/**
 * A simple data container class that contains a part string that is part of a parent string with the 
 * index of the part string into the parent string.
 */
public class FieldStringInfo {

    private final int offset;
    private final String parentString;
    private final String fieldString;

    /**
     * @param parentString The parent string
     * @param fieldString The part string that exists within the parent
     * @param offset the offset of the part string into the parent
     */
    public FieldStringInfo( String parentString, String fieldString, int offset ) {
        this.parentString = parentString;
        this.fieldString = fieldString;
        this.offset = offset;        
    }

    /**
     * The offset of the part string into the parent string
     * @return The offset of the part string into the parent string
     */
    public int getOffset() {
        return offset;
    }

    /**
     * The string that contains the field string
     * @return The string that contains the field string
     */
    public String getParentString() {
        return parentString;
    }

    /**
     * The string that exists within the parent string.
     * @return The string that exists within the parent string.
     */
    public String getFieldString() {
        return fieldString;
    }
    
    @Override
    public String toString() {
        return getClass().getSimpleName() + "[\nfieldString=" + fieldString + 
            ",\nparentString=" + parentString + "\n]";
    }
}
