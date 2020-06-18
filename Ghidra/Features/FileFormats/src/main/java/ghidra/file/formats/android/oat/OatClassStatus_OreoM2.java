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
package ghidra.file.formats.android.oat;

import java.lang.reflect.Field;

import ghidra.program.model.data.*;
import ghidra.util.UniversalIdGenerator;

/**
 * 
 * See https://android.googlesource.com/platform/art/+/marshmallow-release/runtime/mirror/class.h
 *
 */
public final class OatClassStatus_OreoM2 {

	/**
	 *  Class that's temporarily used till class linking time
	 *  has its (vtable) size figured out and has been cloned to one with the
	 *  right size which will be the one used later. The old one is retired and
	 *  will be gc'ed once all refs to the class point to the newly
	 *  cloned version.
	 */
	public final static short kStatusRetired = -3;

	/**
	 *  Class is erroneous. We need to distinguish between classes that 
	 *  have been resolved and classes that have not. This is important 
	 *  because the const-class instruction needs to return a previously 
	 *  resolved class even if its subsequent initialization failed. 
	 *  We also need this to decide whether to wrap a previous initialization 
	 *  failure in ClassDefNotFound error or not.
	 */
	public final static short kStatusErrorResolved = -2;

	/**
	 *  Class is erroneous. We need to distinguish between classes that 
	 *  have been resolved and classes that have not. This is important 
	 *  because the const-class instruction needs to return a previously 
	 *  resolved class even if its subsequent initialization failed. 
	 *  We also need this to decide whether to wrap a previous initialization 
	 *  failure in ClassDefNotFound error or not.
	 */
	public final static short kStatusErrorUnresolved = -1;

	/**
	 * If a Class cannot be found in the class table by FindClass, 
	 * it allocates an new one with AllocClass in the kStatusNotReady 
	 * and calls LoadClass. Note if it does find a class, it may 
	 * not be kStatusResolved and it will try to push it forward toward kStatusResolved.
	 */
	public final static short kStatusNotReady = 0;

	/**
	 * LoadClass populates with Class with information from the DexFile, 
	 * moving the status to kStatusIdx, indicating that the Class value 
	 * in super_class_ has not been populated. The new Class can 
	 * then be inserted shorto the classes table.
	 */
	public final static short kStatusIdx = 1;

	/**
	 * After taking a lock on Class, the ClassLinker will attempt 
	 * to move a kStatusIdx class forward to kStatusLoaded by using 
	 * ResolveClass to initialize the super_class_ and ensuring the 
	 * shorterfaces are resolved.
	 */
	public final static short kStatusLoaded = 2;

	/**
	 * Class is just cloned with the right size from temporary 
	 * class that's acting as a placeholder for linking. The old 
	 * class will be retired. New class is set to this status first 
	 * before moving on to being resolved.
	 */
	public final static short kStatusResolving = 3;

	/**
	 * Still holding the lock on Class, the ClassLinker
	 * shows linking is complete and fields of the Class populated by making
	 * it kStatusResolved. Java allows circularities of the form where a super
	 * class has a field that is of the type of the sub class. We need to be able
	 * to fully resolve super classes while resolving types for fields.
	 */
	public final static short kStatusResolved = 4;

	/** In the process of being verified. */
	public final static short kStatusVerifying = 5;

	/**
	 * The verifier sets a class to this state if it encounters a soft 
	 * failure at compile time. This often happens when there are unresolved 
	 * classes in other dex files, and this status marks a class as 
	 * needing to be verified again at runtime.
	 */
	public final static short kStatusRetryVerificationAtRuntime = 6;

	/** Retrying verification at runtime. */
	public final static short kStatusVerifyingAtRuntime = 7;

	/** Logically part of linking; done pre-init. */
	public final static short kStatusVerified = 8;

	/** Superclass validation part of init done. */
	public final static short kStatusSuperclassValidated = 9;

	/** Class init in progress. */
	public final static short kStatusInitializing = 10;

	/** Ready to go. */
	public final static short kStatusInitialized = 11;

	public final static short kStatusMax = 12;

	/**
	 * Returns the field name for the given value. 
	 * If not found, simply returns a hex string of the value.
	 */
	public static String toString(short value) {
		for (Field field : OatClassStatus_OreoM2.class.getDeclaredFields()) {
			try {
				Object obj = field.get(null);
				if (obj != null && obj.equals(value)) {
					return field.getName();
				}
			}
			catch (Exception e) {
				//ignore...
			}
		}
		return OatClassStatus_OreoM2.class.getSimpleName() + ":0x" + Integer.toHexString(value);
	}

	public static DataType toDataType() {
		EnumDataType enumDataType =
			new EnumDataType(OatClassStatus_OreoM2.class.getSimpleName(), 2);
		for (Field field : OatClassStatus_OreoM2.class.getDeclaredFields()) {
			try {
				Object obj = field.get(null);
				enumDataType.add(field.getName(), (short) obj);
			}
			catch (Exception e) {
				e.printStackTrace();
				//ignore...
			}
		}
		enumDataType.setCategoryPath(new CategoryPath("/oat"));
		return enumDataType;
	}

}
