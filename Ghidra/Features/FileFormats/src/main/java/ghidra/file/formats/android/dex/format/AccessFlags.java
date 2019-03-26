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

public final class AccessFlags {

	public final static int ACC_PUBLIC = 0x1;// public: visible everywhere public: visible everywhere public: visible everywhere
	public final static int ACC_PRIVATE = 0x2;// * private: only visible to defining class private: only visible to defining class private: only visible to defining class
	public final static int ACC_PROTECTED = 0x4;// * protected: visible to package and subclasses protected: visible to package and subclasses protected: visible to package and subclasses public final
	public final static int ACC_STATIC = 0x8;// * static: is not constructed with an outer this reference static: global to defining class static: does not take a this argument
	public final static int ACC_FINAL = 0x10;// final: not subclassable final: immutable after construction final: not overridable
	public final static int ACC_SYNCHRONIZED = 0x20;// synchronized: associated lock automatically acquired around call to this method. Note: This is only valid to set when ACC_NATIVE is also set.
	public final static int ACC_VOLATILE = 0x40;// volatile: special access rules to help with thread safety
	public final static int ACC_BRIDGE = 0x40;// bridge method, added automatically by compiler as a type-safe bridge
	public final static int ACC_TRANSIENT = 0x80;// transient: not to be saved by default serialization
	public final static int ACC_VARARGS = 0x80;// last argument should be treated as a "rest" argument by compiler
	public final static int ACC_NATIVE = 0x100;// native: implemented in native code
	public final static int ACC_INTERFACE = 0x200;// interface: multiply-implementable abstract class
	public final static int ACC_ABSTRACT = 0x400;// abstract: not directly instantiable abstract: unimplemented by this class
	public final static int ACC_STRICT = 0x800;// strictfp: strict rules for floating-point arithmetic
	public final static int ACC_SYNTHETIC = 0x1000;// not directly defined in source code not directly defined in source code not directly defined in source code
	public final static int ACC_ANNOTATION = 0x2000;// declared as an annotation class
	public final static int ACC_ENUM = 0x4000;// declared as an enumerated type declared as an enumerated value
	// (unused) 0x8000
	public final static int ACC_CONSTRUCTOR = 0x10000;// constructor method (class or instance initializer)
	public final static int ACC_DECLARED_SYNCHRONIZED = 0x20000;// declared synchronized. Note: This has no effect on execution (other than in reflection of this flag, per se).

	public final static String toString( int value ) {
		StringBuilder builder = new StringBuilder( );
		try {
			Field [] fields = AccessFlags.class.getDeclaredFields( );
			for ( Field field : fields ) {
				if ( ( field.getInt( null ) & value ) != 0 ) {
					builder.append( "\t" + field.getName( ) + "\n" );
				}
			}
		}
		catch ( Exception e ) {
			// ignore
		}
		return builder.toString( );
	}
}
