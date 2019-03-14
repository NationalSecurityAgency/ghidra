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

public final class MapItemTypeCodes {

	public final static short TYPE_HEADER_ITEM = 0x0000;// 0x70
	public final static short TYPE_STRING_ID_ITEM = 0x0001;// 0x04
	public final static short TYPE_TYPE_ID_ITEM = 0x0002;// 0x04
	public final static short TYPE_PROTO_ID_ITEM = 0x0003;// 0x0c
	public final static short TYPE_FIELD_ID_ITEM = 0x0004;// 0x08
	public final static short TYPE_METHOD_ID_ITEM = 0x0005;// 0x08
	public final static short TYPE_CLASS_DEF_ITEM = 0x0006;// 0x20
	public final static short TYPE_MAP_LIST = 0x1000;// 4 + (item.size * 12)
	public final static short TYPE_TYPE_LIST = 0x1001;// 4 + (item.size * 2)
	public final static short TYPE_ANNOTATION_SET_REF_LIST = 0x1002;// 4 + (item.size * 4)
	public final static short TYPE_ANNOTATION_SET_ITEM = 0x1003;// 4 + (item.size * 4)
	public final static short TYPE_CLASS_DATA_ITEM = 0x2000;// implicit; must parse
	public final static short TYPE_CODE_ITEM = 0x2001;// implicit; must parse
	public final static short TYPE_STRING_DATA_ITEM = 0x2002;// implicit; must parse
	public final static short TYPE_DEBUG_INFO_ITEM = 0x2003;// implicit; must parse
	public final static short TYPE_ANNOTATION_ITEM = 0x2004;// implicit; must parse
	public final static short TYPE_ENCODED_ARRAY_ITEM = 0x2005;// implicit; must parse
	public final static short TYPE_ANNOTATIONS_DIRECTORY_ITEM = 0x2006;// implicit; must parse

	public final static String toString( short type ) {
		try {
			Field [] fields = MapItemTypeCodes.class.getDeclaredFields( );
			for ( Field field : fields ) {
				if ( field.getShort( null ) == type ) {
					return field.getName( );
				}
			}
		}
		catch ( Exception e ) {
			// ignore
		}
		return "Type:" + type;
	}
}
