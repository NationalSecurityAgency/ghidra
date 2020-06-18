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

public final class MethodHandleType {

	/** a setter for a given static field. */
	public final static short kStaticPut = 0x0000;
	/**  a getter for a given static field. */
	public final static short kStaticGet = 0x0001;
	/** a setter for a given instance field. */
	public final static short kInstancePut = 0x0002;
	/** a getter for a given instance field. */
	public final static short kInstanceGet = 0x0003;
	/** an invoker for a given static method. */
	public final static short kInvokeStatic = 0x0004;
	/**
	 * invoke_instance : an invoker for a given instance method.
	 * This can be any non-static method on any class (or interface) 
	 * except for ?<init>?.
	 */
	public final static short kInvokeInstance = 0x0005;
	/** an invoker for a given constructor. */
	public final static short kInvokeConstructor = 0x0006;
	/** an invoker for a direct (special) method. */
	public final static short kInvokeDirect = 0x0007;
	/** an invoker for an interface method. */
	public final static short kInvokeInterface = 0x0008;
	public final static short kLast = kInvokeInterface;

	public final static String toString(short type) {
		try {
			Field[] fields = MethodHandleType.class.getDeclaredFields();
			for (Field field : fields) {
				if (field.getShort(null) == type) {
					return field.getName();
				}
			}
		}
		catch (Exception e) {
			// ignore
		}
		return "MethodHandleType:" + type;
	}
}
