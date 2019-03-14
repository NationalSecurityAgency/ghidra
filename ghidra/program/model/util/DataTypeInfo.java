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

public class DataTypeInfo {
    protected final Object dataTypeHandle;
    protected final int dataTypeLength;
    protected final int dataTypeAlignment;

    /**
     * Constructor for DataTypeInfo.
     * 
     * @param dataTypeHandle
     *            any Object providing identity for this data type
     * @param dataTypeLength
     *            the length of the data type
     * @param dataTypeAlignment
     *            the alignment of the data type
     */
    public DataTypeInfo(Object dataTypeHandle, int dataTypeLength,
            int dataTypeAlignment) {
        this.dataTypeHandle = dataTypeHandle;
        this.dataTypeLength = dataTypeLength;
        this.dataTypeAlignment = dataTypeAlignment;
    }

    /**
     * "Copy" constructor used only by CompositeDataTypeElementInfo
     * 
     * @param dataTypeInfo
     *            the source DataTypeInfo
     */
    DataTypeInfo(DataTypeInfo dataTypeInfo) {
        this.dataTypeHandle = dataTypeInfo.dataTypeHandle;
        this.dataTypeLength = dataTypeInfo.dataTypeLength;
        this.dataTypeAlignment = dataTypeInfo.dataTypeAlignment;
    }

    public Object getDataTypeHandle() {
        return dataTypeHandle;
    }

    public int getDataTypeLength() {
        return dataTypeLength;
    }

    public int getDataTypeAlignment() {
        return dataTypeAlignment;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + dataTypeAlignment;
        result = prime * result
                + ((dataTypeHandle == null) ? 0 : dataTypeHandle.hashCode());
        result = prime * result + dataTypeLength;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof DataTypeInfo))
            return false;
        final DataTypeInfo other = (DataTypeInfo) obj;
        if (dataTypeAlignment != other.dataTypeAlignment)
            return false;
        if (dataTypeHandle == null) {
            if (other.dataTypeHandle != null)
                return false;
        } else if (!dataTypeHandle.equals(other.dataTypeHandle))
            return false;
        if (dataTypeLength != other.dataTypeLength)
            return false;
        return true;
    }
}
