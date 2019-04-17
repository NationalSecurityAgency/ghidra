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
package ghidra.app.util.bin.format.pe;

/**
 * A class to hold the information extracted from a 
 * export data directory.
 * 
 * NOTE:
 * This class is simply a storage class created for 
 * parsing the PE header data structures.
 * It does not map back to a PE data data structure.
 * 
 * 
 */
public class ExportInfo {
	private long address;
    private int ordinal;
	private String name;
    private String comment;
    private boolean forwarded;

    ExportInfo(long address, int ordinal, String name, String cmt, boolean forwarded) {
        this.address   = address;
        this.ordinal   = ordinal;
        this.name      = name;
        this.comment   = cmt;
        this.forwarded = forwarded;
    }

	/**
	 * Returns the adjusted address where the export occurs.
	 * @return the adjusted address where the export occurs
	 */
	public long getAddress() {
		return address;
	}

	/**
	 * Returns the ordinal value of the export.
	 * @return the ordinal value of the export
	 */
    public int getOrdinal() {
        return ordinal;
    }

	/**
	 * Returns the name of the export.
	 * @return the name of the export
	 */
    public String getName() {
        return name;
    }

	/**
	 * Returns a comment string containing extra information about the export.
	 * @return a comment string containing extra information about the export
	 */
    public String getComment() {
        return comment;
    }

	/**
	 * Returns true of this export is going to be forwarded.
	 * Generally, a forwarded export just through another export.
	 * @return true of this export is going to be forwarded
	 */
    public boolean isForwarded() {
        return forwarded;
    }

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
    public String toString() {
		return ordinal+" "+name+" at "+Long.toHexString(address);
	}
}
