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
package ghidra.app.util.datatype.microsoft;

import ghidra.app.util.datatype.microsoft.GuidUtil.GuidType;
import ghidra.util.*;

/**
 * 
 *
 */
public class NewGuid {
	
	public static int size = 16;
	private long [] data = new long[4];
	private byte [] allBytes = new byte[size];
	private String version;
	private String name;
	private GuidType type;
	
	/**
	 * Creates a GUID data type.
	 */
	public NewGuid(DataConverter conv, String GUID, String delim, GuidType type, boolean hasVersion) {    
	    this.type = type;
	    
	    String strippedGUID = GUID.replaceAll(delim, "");
	    strippedGUID = strippedGUID.substring(0, strippedGUID.indexOf(" "));
	    if (strippedGUID.length() != size*2) {
	        Msg.error(this, "ERROR PARSING GUID: "+GUID);
	    }
	    data[0] = (0xFFFFFFFFL & NumericUtilities.parseHexLong(strippedGUID.substring(0,   8)));
	    String str = strippedGUID.substring(8, 16);
	    str = str.substring(4,8)+str.substring(0,4);
	    data[1] = (0xFFFFFFFFL & NumericUtilities.parseHexLong(str));
	    str = strippedGUID.substring(16, 24);
	    str = str.substring(6,8)+str.substring(4,6)+str.substring(2,4)+str.substring(0,2);
	    data[2] = (0xFFFFFFFFL & NumericUtilities.parseHexLong(str));
	    str = strippedGUID.substring(24, 32);
	    str = str.substring(6,8)+str.substring(4,6)+str.substring(2,4)+str.substring(0,2);
	    data[3] = (0xFFFFFFFFL & NumericUtilities.parseHexLong(str));
	    
	    for (int i = 0; i < data.length; i++) {
	        conv.getBytes((int)data[i], allBytes, i*4);
	    }
	    
	    String left = GUID.substring(36);
	    if (hasVersion) {
	        int vpos = left.indexOf("v");
	        if (vpos > 0) {
		        left = left.substring(vpos);
		        int sppos = left.indexOf(" ");
		        if (sppos > 0) {
		        	version = left.substring(0, sppos);
		        } else {
		            version = left.substring(0);
		        }
		        left = left.substring(version.length());
	        }
	    }
	    name = left.substring(left.indexOf(" ")+1);
	}
	
	public NewGuid(DataConverter conv, byte [] bytes, int offset) {
	    if (bytes.length < offset+data.length*4) return;
	    for (int i = 0; i < data.length; i++) {
	        data[i] = 0xFFFFFFFFL & conv.getInt(bytes, offset+i*4);
	        conv.getBytes((int)data[i], allBytes, i*4);
	    }
	}

	public String toString(String delim, boolean useName) {
	    if (name != null && useName) {
	    	return name;
	    }
        String retVal = type.toString()+delim;
		retVal += Conv.toHexString((int)data[0])+delim;
		retVal += Conv.toHexString((short)(data[1]))+delim;
		retVal += Conv.toHexString((short)(data[1]>>16))+delim;
		for (int i = 0; i < 4; i++) {
		    retVal += Conv.toHexString((byte)(data[2]>>i*8)); 
		    if (i == 1) retVal += delim;
		}
		for (int i = 0; i < 4; i++) {
		    retVal += Conv.toHexString((byte)(data[3]>>i*8)); 
		}
		return retVal;
	}
	
	
	public boolean isOK() {
	    for (int i = 0; i < data.length; i++) {
	        if ((data[i] != 0) || (data[i] != 0xFFFFFFFFL)) {
	            return true;
	        }
	    }
	    return false;
	}
	
    public static boolean isOKForGUID(byte [] bytes, int offset) {
        // NB: (not really sure what's going on here)
        if (bytes.length < offset+size) return false;
        if ((bytes[offset+7] == (byte)0x0)  && (bytes[offset+8] == (byte)0xC0) && (bytes[offset+15] == (byte)0x46))         		return true;
        if ((bytes[offset+7] >= (byte)0x10) && (bytes[offset+7] <= (byte)0x12) && ((bytes[offset+8] & (byte)0xC0) == (byte)0x80)) 	return true;
        if (((bytes[offset+7] & (byte)0xF0) == (byte)0x40) && ((bytes[offset+8] & (byte)0xC0) == (byte)0x80))                     	return true;
        return false;
    }
    
    public static boolean isZeroGUID(byte [] bytes, int offset) {
        if (bytes.length < offset+size) return false;
        for (int i = 0; i < size; i++) {
            if (bytes[offset+i] != 0) return false;
        }
        return true;
    }
    
    @Override
    public boolean equals(Object test) {
        if (!(test instanceof NewGuid)) return false;
        byte [] testBytes = ((NewGuid)test).getBytes();
        for (int i = 0; i < allBytes.length; i++) {
            if (allBytes[i] != testBytes[i])
                return false;
        }
        return true;
    }
    @Override
    public int hashCode() {
        return (int)(data[0]^data[1]^data[2]^data[3]);
    }
    
	public byte []  getBytes()   {return allBytes;}
	public String   getName()    {return toString("-", true);}
	public String   getVersion() {return version;}
	public GuidType getType()    {return type;}
	
}
