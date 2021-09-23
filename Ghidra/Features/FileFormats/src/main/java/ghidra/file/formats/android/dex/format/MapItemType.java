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
package ghidra.file.formats.android.dex.format;

import java.lang.reflect.Field;

/**
 * Map item type codes.
 */
public final class MapItemType {

	public final static short kDexTypeHeaderItem = 0x0000;
	public final static short kDexTypeStringIdItem = 0x0001;
	public final static short kDexTypeTypeIdItem = 0x0002;
	public final static short kDexTypeProtoIdItem = 0x0003;
	public final static short kDexTypeFieldIdItem = 0x0004;
	public final static short kDexTypeMethodIdItem = 0x0005;
	public final static short kDexTypeClassDefItem = 0x0006;
	public final static short kDexTypeCallSiteIdItem = 0x0007;
	public final static short kDexTypeMethodHandleItem = 0x0008;
	public final static short kDexTypeMapList = 0x1000;
	public final static short kDexTypeTypeList = 0x1001;
	public final static short kDexTypeAnnotationSetRefList = 0x1002;
	public final static short kDexTypeAnnotationSetItem = 0x1003;
	public final static short kDexTypeClassDataItem = 0x2000;
	public final static short kDexTypeCodeItem = 0x2001;
	public final static short kDexTypeStringDataItem = 0x2002;
	public final static short kDexTypeDebugInfoItem = 0x2003;
	public final static short kDexTypeAnnotationItem = 0x2004;
	public final static short kDexTypeEncodedArrayItem = 0x2005;
	public final static short kDexTypeAnnotationsDirectoryItem = 0x2006;
	public final static short kDexTypeHiddenapiClassData = (short) 0xF000;

	public final static String toString(short type) {
		try {
			Field[] fields = MapItemType.class.getDeclaredFields();
			for (Field field : fields) {
				if (field.getShort(null) == type) {
					return field.getName();
				}
			}
		}
		catch (Exception e) {
			// ignore
		}
		return "MapItemType:" + type;
	}
}
