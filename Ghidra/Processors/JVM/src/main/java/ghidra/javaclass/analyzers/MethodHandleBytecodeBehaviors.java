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
package ghidra.javaclass.analyzers;

import ghidra.util.Msg;

import java.lang.reflect.Field;

public final class MethodHandleBytecodeBehaviors {

	/** getfield C.f:T */
	public final static int REF_getField = 1;

	/** getstatic C.f:T */
	public final static int REF_getStatic = 2;

	/** putfield C.f:T */
	public final static int REF_putField = 3;

	/** putstatic C.f:T */
	public final static int REF_putStatic = 4;

	/** invokevirtual C.m:(A*)T */
	public final static int REF_invokeVirtual = 5;

	/** invokestatic C.m:(A*)T */
	public final static int REF_invokeStatic = 6;

	/** invokespecial C.m:(A*)T */
	public final static int REF_invokeSpecial = 7;

	/** new C; dup; invokespecial C.<init>:(A*)void */
	public final static int REF_newInvokeSpecial = 8;

	/** invokeinterface C.m:(A*)T */
	public final static int REF_invokeInterface = 9;

	public final static String getName( int kind ) {
		Field [] fields = MethodHandleBytecodeBehaviors.class.getDeclaredFields( );
		for (Field field : fields) {
			if (field.getName( ).startsWith( "REF_" )) {
				try {
					Integer value = (Integer) field.get( null );
					if (value == kind) {
						return field.getName( );
					}
				}
				catch (Exception e) {
					Msg.error( MethodHandleBytecodeBehaviors.class, "Unexpected Exception: " + e.getMessage( ), e );
				}
			}
		}
		return "Unrecognized kind: 0x" + Integer.toHexString( kind );
	}
}
