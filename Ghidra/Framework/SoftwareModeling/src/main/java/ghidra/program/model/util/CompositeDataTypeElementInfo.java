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
package ghidra.program.model.util;

public class CompositeDataTypeElementInfo extends DataTypeInfo {
    private final int dataTypeOffset;

    /**
     * Constructor for CompositeDataTypeElementInfo.
     * 
     * @param dataTypeHandle
     *            any Object providing identity for this data type
     * @param dataTypeOffset
     *            the offset of the element within the outer composite data type
     * @param dataTypeLength
     *            the length of the data type
     * @param dataTypeAlignment
     *            the alignment of the data type
     */
    public CompositeDataTypeElementInfo(Object dataTypeHandle,
            int dataTypeOffset, int dataTypeLength, int dataTypeAlignment) {
        super(dataTypeHandle, dataTypeLength, dataTypeAlignment);
        this.dataTypeOffset = dataTypeOffset;
    }

    /**
     * Constructor for CompositeDataTypeElementInfo (copy-ish).
     * 
     * @param dataTypeInfo
     *            the dataType this CompositeDataTypeElementInfo is based upon
     * @param dataTypeOffset
     *            the offset of the element within the outer composite data type
     */
    public CompositeDataTypeElementInfo(DataTypeInfo dataTypeInfo,
            int dataTypeOffset) {
        super(dataTypeInfo);
        this.dataTypeOffset = dataTypeOffset;
    }

    public int getDataTypeOffset() {
        return dataTypeOffset;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + dataTypeOffset;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!super.equals(obj))
            return false;
        if (!(obj instanceof CompositeDataTypeElementInfo))
            return false;
        final CompositeDataTypeElementInfo other = (CompositeDataTypeElementInfo) obj;
        if (dataTypeOffset != other.dataTypeOffset)
            return false;
        return true;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(dataTypeHandle);
        sb.append("/");
        sb.append(dataTypeAlignment);
        sb.append(":(");
        sb.append(dataTypeOffset);
        sb.append(",");
        sb.append(dataTypeLength);
        sb.append(")");
        return sb.toString();
    }
}
