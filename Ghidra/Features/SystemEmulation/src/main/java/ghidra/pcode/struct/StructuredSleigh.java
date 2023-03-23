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
package ghidra.pcode.struct;

import java.lang.annotation.*;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.lifecycle.Internal;
import ghidra.pcode.emu.unix.AbstractEmuUnixSyscallUseropLibrary;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.SleighPcodeUseropDefinition.Builder;
import ghidra.pcode.exec.SleighPcodeUseropDefinition.Factory;
import ghidra.pcode.floatformat.FloatFormatFactory;
import ghidra.pcode.struct.DefaultVar.Check;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;
import utilities.util.AnnotationUtilities;

/**
 * The primary class for using the "structured sleigh" DSL
 * 
 * <p>
 * This provides some conveniences for generating Sleigh source code, which is otherwise completely
 * typeless and lacks basic control structure. In general, the types are not used so much for type
 * checking as they are for easing access to fields of C structures, array indexing, etc.
 * Furthermore, it becomes possible to re-use code when data types differ among platforms, so long
 * as those variations are limited to field offsets and type sizes.
 * 
 * <p>
 * Start by declaring an extension of {@link StructuredSleigh}. Then put any necessary "forward
 * declarations" as fields of the class. Then declare methods annotated with
 * {@link StructuredUserop}. Inside those methods, all the protected methods of this class are
 * accessible, providing a DSL (as far as Java can provide :/ ) for writing Sleigh code. For
 * example:
 * 
 * <pre>
 * class MyStructuredPart extends StructuredSleigh {
 * 	Var r0 = lang("r0", "/long");
 * 
 * 	protected MyStructuredPart() {
 * 		super(program);
 * 	}
 * 
 * 	&#64;StructuredUserop
 * 	public void my_userop() {
 * 		r0.set(0xdeadbeef);
 * 	}
 * }
 * </pre>
 * 
 * <p>
 * This will simply generate the source "{@code r0 = 0xdeadbeef:4}", but it also provides all the
 * scaffolding to compile and invoke the userop as in a {@link PcodeUseropLibrary}. Internal methods
 * -- which essentially behave like macros -- may be used, so only annotate methods to export as
 * userops. For a more complete and practical example of using structured sleigh in a userop
 * library, see {@link AbstractEmuUnixSyscallUseropLibrary}.
 * 
 * <p>
 * Structured sleigh is also usable in a more standalone manner:
 * 
 * <pre>
 * StructuredSleigh ss = new StructuredSleigh(compilerSpec) {
 * 	&#64;StructuredUserop
 * 	public void my_userop() {
 * 		// Something interesting, I'm sure
 * 	}
 * };
 * 
 * SleighPcodeUseropDefinition&lt;Object&gt; myUserop = ss.generate().get("my_userop");
 * // To print source
 * myUserop.getLines().forEach(System.out::print);
 * 
 * // To compile for given parameters (none in this case) and print the p-code
 * Register r0 = lang.getRegister("r0");
 * System.out.println(myUserop.programFor(new Varnode(r0.getAddress(), r0.getNumBytes()), List.of(),
 * 	PcodeUseropLibrary.NIL));
 * </pre>
 * 
 * <p>
 * Known limitations:
 * <ul>
 * <li>Recursion is not really possible. Currently, local variables of a userop do not actually get
 * their own unique storage per invocation record. Furthermore, it's possible that local variable in
 * different userop definition will be assigned the same storage location, meaning they could be
 * unintentionally aliased if one invokes the other. Care should be taken when invoking one
 * sleigh-based userop from another, or it should be avoided altogether until this limitation is
 * addressed. It's generally safe to allow such invocations at the tail.</li>
 * <li>Parameters are passed by reference. Essentially, the formal argument becomes an alias to its
 * parameter. This is more a feature, but can be surprising if C semantics are expected.</li>
 * <li>Calling one Structured Sleigh userop from another still requires a "external declaration" of
 * the callee, despite being defined in the same "compilation unit."</li>
 * </ul>
 */
public class StructuredSleigh {
	private static final Map<Class<?>, Set<Method>> CACHE_BY_CLASS = new HashMap<>();

	private static Set<Method> collectDefinitions(Class<? extends StructuredSleigh> cls) {
		return AnnotationUtilities.collectAnnotatedMethods(StructuredUserop.class, cls);
	}

	/**
	 * "Export" a method as a p-code userop implemented using p-code compiled from structured Sleigh
	 *
	 * <p>
	 * This is applied to methods used to generate Sleigh source code. Take note that the method is
	 * only invoked once (for a given library instance) to generate code. Thus, beware of
	 * non-determinism during code generation. For example, implementing something like
	 * {@code rdrnd} in structured Sleigh is rife with peril. Take the following implementation:
	 * 
	 * <pre>
	 * &#64;StructuredUserop
	 * public void rdrnd() {
	 * 	r0.set(Random.nextLong()); // BAD: Die rolled once at compile time
	 * }
	 * </pre>
	 * 
	 * <p>
	 * The random number will be generated once at structured Sleigh compilation time, and then that
	 * same number used on every invocation of the p-code userop. Instead, this userop should be
	 * implemented using a Java callback, i.e., {@link AnnotatedPcodeUseropLibrary.PcodeUserop}.
	 * 
	 * <p>
	 * The userop may accept parameters and return a result. To accept parameters, declare them in
	 * the Java method signature and annotate them with {@link Param}. To return a result, name the
	 * appropriate type in the {@link #type()} attribute and use
	 * {@link StructuredSleigh#_result(RVal)}. The Java return type of the method must still be
	 * {@code void}. Note that parameters are passed by reference, so results can also be
	 * communicated by setting a parameter's value.
	 */
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.METHOD)
	protected @interface StructuredUserop {
		/**
		 * The data type path for the "return type" of the userop. See
		 * {@link StructuredSleigh#type(String)}.
		 */
		String type() default "void";
	}

	/**
	 * Declare a parameter of the p-code userop
	 * 
	 * <p>
	 * This is attached to parameters of methods annotated with {@link StructuredUserop}, providing
	 * the type and name of the parameter. The Java type of the parameter must be {@link Var}. For
	 * example:
	 * 
	 * <pre>
	 * &#64;StructuredUserop
	 * public void twice(@Param(name = "p0", type = "void *") Var p0) {
	 * 	_result(p0.mul(2));
	 * }
	 * </pre>
	 */
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	protected @interface Param {
		/**
		 * The data type path for the type of the parameter. See
		 * {@link StructuredSleigh#type(String)}.
		 */
		String type();

		/**
		 * The name of the parameter in the output Sleigh code
		 * 
		 * <p>
		 * If the variable is referenced via {@link StructuredSleigh#s(String)} or
		 * {@link StructuredSleigh#e(String)}, then is it necessary to specify the name used in the
		 * Sleigh code. Otherwise, the name is typically derived from the Java parameter name, which
		 * Java platforms are not required to preserve. If the variable is referenced only by its
		 * handle, then the name will be consistent and unique in the generated Sleigh code. When
		 * diagnosing Structured Sleigh compilation issues, it may be desirable to specify the
		 * variable name, regardless.
		 */
		String name() default "";
	}

	/**
	 * The declaration of an "imported" userop
	 * 
	 * <p>
	 * Because Sleigh is typeless, structured Sleigh needs additional type information about the
	 * imported userop. The referenced userop may be implemented by another library and may be a
	 * Java callback or a p-code based userop, or something else. Note that if the userop is
	 * missing, it might not be detected until the calling Sleigh code is invoked for the first
	 * time.
	 */
	protected interface UseropDecl {
		/**
		 * Get the userop's return type
		 * 
		 * @return the return type
		 */
		DataType getReturnType();

		/**
		 * Get the name of the userop
		 * 
		 * @return the name
		 */
		String getName();

		/**
		 * Get the parameter types of the userop
		 * 
		 * @return the types, in order of parameters
		 */
		List<DataType> getParameterTypes();

		/**
		 * Generate an invocation of the userop
		 * 
		 * <p>
		 * If the userop has a result type, then the resulting statement will also have a value. If
		 * the user has a {@code void} result type, the "value" should not be used. Otherwise, a
		 * warning will likely be generated, and the "result value" will be undefined.
		 * 
		 * @param args the arguments to pass
		 * @return a handle to the statement
		 */
		StmtWithVal call(RVal... args);
	}

	/**
	 * A value which can only be used on the right-hand side of an assignment
	 */
	protected interface RVal {
		/**
		 * Get the type of the value
		 * 
		 * @return the type
		 */
		DataType getType();

		/**
		 * Cast the value to the given type
		 * 
		 * <p>
		 * This functions like a C-style pointer cast. There are no implied operations or
		 * conversions. Notably, casting between integers and floats is just a re-interpretation of
		 * the underlying bits.
		 * 
		 * @param type the type
		 * @return a handle to the resulting value
		 */
		RVal cast(DataType type);

		/**
		 * Generate a dereference (in the C sense)
		 * 
		 * <p>
		 * The value is treated as an address, and the result is essentially a variable in the given
		 * target address space.
		 * 
		 * @param space the address space of the result
		 * @return a handle to the resulting value
		 */
		LVal deref(AddressSpace space);

		/**
		 * Generate a dereference (in the C sense) in the default address space
		 * 
		 * @return a handle to the resulting value
		 */
		LVal deref();

		/**
		 * Generate boolean inversion
		 * 
		 * @return a handle to the resulting value
		 */
		RVal notb();

		/**
		 * Generate integer (bitwise) inversion
		 * 
		 * @return a handle to the resulting value
		 */
		RVal noti();

		/**
		 * Generate integer comparison: equal to
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal eq(RVal rhs);

		/**
		 * Generate integer comparison: equal to
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal eq(long rhs);

		/**
		 * Generate float comparison: equal to
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal eqf(RVal rhs);

		/**
		 * Generate integer comparison: not equal to
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal neq(RVal rhs);

		/**
		 * Generate integer comparison: not equal to
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal neq(long rhs);

		/**
		 * Generate float comparison: not equal to
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal neqf(RVal rhs);

		/**
		 * Generate unsigned integer comparison: less than
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal ltiu(RVal rhs);

		/**
		 * Generate unsigned integer comparison: less than
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal ltiu(long rhs);

		/**
		 * Generate signed integer comparison: less than
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal ltis(RVal rhs);

		/**
		 * Generate signed integer comparison: less than
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal ltis(long rhs);

		/**
		 * Generate unsigned integer comparison: less than
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal ltf(RVal rhs);

		/**
		 * Generate unsigned integer comparison: greater than
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal gtiu(RVal rhs);

		/**
		 * Generate unsigned integer comparison: greater than
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal gtiu(long rhs);

		/**
		 * Generate signed integer comparison: greater than
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal gtis(RVal rhs);

		/**
		 * Generate signed integer comparison: greater than
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal gtis(long rhs);

		/**
		 * Generate float comparison: greater than
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal gtf(RVal rhs);

		/**
		 * Generate unsigned integer comparison: less than or equal to
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal lteiu(RVal rhs);

		/**
		 * Generate unsigned integer comparison: less than or equal to
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal lteiu(long rhs);

		/**
		 * Generate signed integer comparison: less than or equal to
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal lteis(RVal rhs);

		/**
		 * Generate signed integer comparison: less than or equal to
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal lteis(long rhs);

		/**
		 * Generate float comparison: less than or equal to
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal ltef(RVal rhs);

		/**
		 * Generate unsigned integer comparison: greater than or equal to
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal gteiu(RVal rhs);

		/**
		 * Generate unsigned integer comparison: greater than or equal to
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal gteiu(long rhs);

		/**
		 * Generate signed integer comparison: greater than or equal to
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal gteis(RVal rhs);

		/**
		 * Generate signed integer comparison: greater than or equal to
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal gteis(long rhs);

		/**
		 * Generate float comparison: greater than or equal to
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal gtef(RVal rhs);

		/**
		 * Generate boolean or
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal orb(RVal rhs);

		/**
		 * Generate boolean or
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal orb(long rhs);

		/**
		 * Generate an integer (bitwise) or
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal ori(RVal rhs);

		/**
		 * Generate an integer (bitwise) or
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal ori(long rhs);

		/**
		 * Generate boolean exclusive or
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal xorb(RVal rhs);

		/**
		 * Generate boolean exclusive or
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal xorb(long rhs);

		/**
		 * Generate an integer (bitwise) exclusive or
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal xori(RVal rhs);

		/**
		 * Generate an integer (bitwise) exclusive or
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal xori(long rhs);

		/**
		 * Generate boolean and
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal andb(RVal rhs);

		/**
		 * Generate boolean and
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal andb(long rhs);

		/**
		 * Generate an integer (bitwise) and
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal andi(RVal rhs);

		/**
		 * Generate an integer (bitwise) and
		 * 
		 * @param rhs the immediate operand (mask)
		 * @return a handle to the resulting value
		 */
		RVal andi(long rhs);

		/**
		 * Generate bit shift to the left
		 * 
		 * @param rhs the second operand (shift amount)
		 * @return a handle to the resulting value
		 */
		RVal shli(RVal rhs);

		/**
		 * Generate bit shift to the left
		 * 
		 * @param rhs the immediate operand (shift amount)
		 * @return a handle to the resulting value
		 */
		RVal shli(long rhs);

		/**
		 * Generate unsigned bit shift to the right
		 * 
		 * @param rhs the second operand (shift amount)
		 * @return a handle to the resulting value
		 */
		RVal shriu(RVal rhs);

		/**
		 * Generate unsigned bit shift to the right
		 * 
		 * @param rhs the immediate operand (shift amount)
		 * @return a handle to the resulting value
		 */
		RVal shriu(long rhs);

		/**
		 * Generate signed bit shift to the right
		 * 
		 * @param rhs the second operand (shift amount)
		 * @return a handle to the resulting value
		 */
		RVal shris(RVal rhs);

		/**
		 * Generate signed bit shift to the right
		 * 
		 * @param rhs the immediate operand (shift amount)
		 * @return a handle to the resulting value
		 */
		RVal shris(long rhs);

		/**
		 * Generate integer addition
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal addi(RVal rhs);

		/**
		 * Generate integer addition
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal addi(long rhs);

		/**
		 * Generate float addition
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal addf(RVal rhs);

		/**
		 * Generate integer subtraction
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal subi(RVal rhs);

		/**
		 * Generate integer subtraction of an immediate
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal subi(long rhs);

		/**
		 * Generate float subtraction
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal subf(RVal rhs);

		/**
		 * Generate integer multiplication
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal muli(RVal rhs);

		/**
		 * Generate integer multiplication
		 * 
		 * @param rhs the immediate operand
		 * @return a handle to the resulting value
		 */
		RVal muli(long rhs);

		/**
		 * Generate float multiplication
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		RVal mulf(RVal rhs);

		/**
		 * Generate unsigned integer division
		 * 
		 * @param rhs the divisor
		 * @return a handle to the resulting value
		 */
		RVal diviu(RVal rhs);

		/**
		 * Generate unsigned integer division
		 * 
		 * @param rhs the immediate divisor
		 * @return a handle to the resulting value
		 */
		RVal diviu(long rhs);

		/**
		 * Generate signed integer division
		 * 
		 * @param rhs the divisor
		 * @return a handle to the resulting value
		 */
		RVal divis(RVal rhs);

		/**
		 * Generate signed integer division
		 * 
		 * @param rhs the immediate divisor
		 * @return a handle to the resulting value
		 */
		RVal divis(long rhs);

		/**
		 * Generate float division
		 * 
		 * @param rhs the divisor
		 * @return a handle to the resulting value
		 */
		RVal divf(RVal rhs);

		/**
		 * Generate unsigned integer division remainder
		 * 
		 * @param rhs the divisor
		 * @return a handle to the resulting value
		 */
		RVal remiu(RVal rhs);

		/**
		 * Generate unsigned integer division remainder
		 * 
		 * @param rhs the immediate divisor
		 * @return a handle to the resulting value
		 */
		RVal remiu(long rhs);

		/**
		 * Generate signed integer division remainder
		 * 
		 * @param rhs the divisor
		 * @return a handle to the resulting value
		 */
		RVal remis(RVal rhs);

		/**
		 * Generate signed integer division remainder
		 * 
		 * @param rhs the immediate divisor
		 * @return a handle to the resulting value
		 */
		RVal remis(long rhs);
	}

	/**
	 * A value which can be used on either side of an assignment
	 */
	protected interface LVal extends RVal {
		@Override
		LVal cast(DataType type);

		/**
		 * Generate a field offset
		 * 
		 * <p>
		 * This departs subtly from expected C semantics. This value's type is assumed to be a
		 * pointer to a {@link Composite}. That type is retrieved and the field located. This then
		 * generates unsigned addition of that field offset to this value. The type of the result is
		 * a pointer to the type of the field. The C equivalent is "{@code &(val->field)}".
		 * Essentially, it's just address computation. Note that this operator will fail if the type
		 * is not a pointer. It cannot be used directly on the {@link Composite} type.
		 * 
		 * <p>
		 * TODO: Allow direct use on the composite type? Some mechanism for dealing with bitfields?
		 * Bitfields cannot really work if this is just pointer manipulation. If it's also allowed
		 * to manipulate raw bytes of a composite, then bitfield access could work. Assignment would
		 * be odd, but doable. The inputs would be the composite-typed value, the field name, and
		 * the desired field value. The output would be the resulting composite-typed value. For
		 * large structures, though, we'd like to manipulate the least number of bytes possible,
		 * since they'll likely need to be written back out to target memory.
		 * 
		 * @param name the name of the field
		 * @return a handle to the resulting value
		 */
		LVal field(String name);

		/**
		 * Generate an array index
		 * 
		 * <p>
		 * This departs subtly from expected C semantics. This value's type is assumed to be a
		 * pointer to the element type. The size of the element type is computed, and this generates
		 * unsigned multiplcation of the index and size, then addition to this value. The type of
		 * the result is the same as this value's type. The C equivalent is "{@code &(val[index])}".
		 * Essentially, it's just address computation. Note that this operator will fail if the type
		 * is not a pointer. It cannot be used on an {@link Array} type.
		 * 
		 * 
		 * <p>
		 * TODO: Allow use of {@link Array} type? While it's possible for authors to specify pointer
		 * types for their variables, the types of fields they access may not be under their
		 * control. In particular, between {@link #field(String)} and {@link #index(RVal)}, we ought
		 * to support accessing fixed-length array fields.
		 * 
		 * @param index the operand to use as the index into the array
		 * @return a handle to the resulting value
		 */
		LVal index(RVal index);

		/**
		 * Generate an array index
		 * 
		 * @see #index(RVal)
		 * @param index the immediate to use as the index into the array
		 * @return a handle to the resulting value
		 */
		LVal index(long index);

		/**
		 * Assign this value
		 * 
		 * @param rhs the value to assign
		 * @return a handle to the resulting value
		 */
		StmtWithVal set(RVal rhs);

		/**
		 * Assign this value
		 * 
		 * @param rhs the immediate value to assign
		 * @return a handle to the resulting value
		 */
		StmtWithVal set(long rhs);

		/**
		 * Generate in-place integer addition
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		StmtWithVal addiTo(RVal rhs);

		/**
		 * Generate in-place integer addition
		 * 
		 * @param rhs the second operand
		 * @return a handle to the resulting value
		 */
		StmtWithVal addiTo(long rhs);

		/**
		 * Generate an in-place increment (by 1)
		 * 
		 * @return a handle to the resulting value
		 */
		StmtWithVal inc();
	}

	/**
	 * A Sleigh variable
	 */
	protected interface Var extends LVal {
		@Override
		Var cast(DataType type);

		/**
		 * Get the name of the variable as it appears in generated Sleigh code
		 * 
		 * @return the name
		 */
		String getName();
	}

	/**
	 * A Structured Sleigh statement
	 */
	protected interface Stmt {
		// Nothing added
	}

	/**
	 * A Structured Sleigh statement that also has a value
	 */
	protected interface StmtWithVal extends Stmt, RVal {
	}

	/**
	 * Utility: Get the named component (field) from the given composite data type
	 * 
	 * @param composite the type
	 * @param name the name of the component
	 * @return the found component, or null
	 */
	protected static DataTypeComponent findComponentByName(Composite composite, String name) {
		for (DataTypeComponent dtc : composite.getComponents()) {
			if (name.equals(dtc.getFieldName())) {
				return dtc;
			}
		}
		return null;
	}

	/**
	 * An exception for unrecoverable Structured Sleigh compilation errors
	 */
	public static class StructuredSleighError extends RuntimeException {
		protected StructuredSleighError(String message) {
			super(message);
		}

		protected StructuredSleighError(String message, Throwable cause) {
			super(message, cause);
		}
	}

	/**
	 * A generated Sleigh label
	 */
	@Internal
	protected interface Label {
		/**
		 * Borrow this label
		 * 
		 * <p>
		 * This should be used whenever a statement (or its children) may need to generate a goto
		 * using the "next" label passed into it. If "next" is the fall-through label, this will
		 * generate a fresh label. If this label is already fresh, this will "borrow" the label,
		 * meaning references will be generated, but it will not produce another anchor. This is to
		 * prevent generation of duplicate anchors.
		 * 
		 * @return the resulting label
		 */
		abstract Label freshOrBorrow();

		/**
		 * Generate code for this label
		 * 
		 * <p>
		 * This must be the last method called on the label, because it relies on knowing whether or
		 * not the label is actually used. (The Sleigh compiler rejects code if it contains unused
		 * labels.)
		 * 
		 * @return the Sleigh code
		 */
		abstract StringTree genAnchor();

		/**
		 * Generate a reference to this label as it should appear in a Sleigh "{@code goto}"
		 * statement
		 * 
		 * @return the label's expression
		 */
		abstract StringTree ref();

		/**
		 * Generate a goto statement that targets this label
		 * 
		 * @param fall the label following the goto
		 * @return the Sleigh code
		 */
		abstract StringTree genGoto(Label fall);

		/**
		 * Generate a conditional goto statement that targets this label
		 * 
		 * @param cond the condition value
		 * @param fall the label following the goto
		 * @return the Sleigh code
		 */
		abstract StringTree genGoto(RVal cond, Label fall);
	}

	/**
	 * A fresh Sleigh label
	 */
	protected class FreshLabel implements Label {
		// Name will be assigned at use
		private String name = null;

		private String getName() {
			if (name != null) {
				return name;
			}
			return name = "L" + (nextLabel++);
		}

		@Override
		public Label freshOrBorrow() {
			return new BorrowedLabel(this);
		}

		@Override
		public StringTree genAnchor() {
			if (name == null) {
				return StringTree.single("");
			}
			StringTree st = new StringTree();
			st.append("<");
			st.append(name);
			st.append(">\n");
			return st;
		}

		@Override
		public StringTree ref() {
			StringTree st = new StringTree();
			st.append("<");
			st.append(getName());
			st.append(">");
			return st;
		}

		@Override
		public StringTree genGoto(Label fall) {
			if (this == fall) {
				return StringTree.single("");
			}
			StringTree st = new StringTree();
			st.append("goto ");
			st.append(ref());
			st.append(";\n");
			return st;
		}

		@Override
		public StringTree genGoto(RVal cond, Label fall) {
			if (this == fall) {
				return StringTree.single("");
			}
			StringTree st = new StringTree();
			st.append("if ");
			st.append(((RValInternal) cond).generate(null));
			st.append(" ");
			st.append(genGoto(fall));
			return st;
		}
	}

	/**
	 * A label whose anchor placement is already claimed
	 */
	private class BorrowedLabel implements Label {
		protected final FreshLabel borrowed;

		/**
		 * Replicate the given label, but without an anchor
		 * 
		 * @param borrowed the already-fresh label
		 */
		protected BorrowedLabel(FreshLabel borrowed) {
			this.borrowed = borrowed;
		}

		@Override
		public Label freshOrBorrow() {
			return this;
		}

		@Override
		public StringTree genAnchor() {
			return StringTree.single("");
		}

		@Override
		public StringTree ref() {
			return borrowed.ref();
		}

		@Override
		public StringTree genGoto(Label fall) {
			if (this == fall) { // placed will also check
				return StringTree.single("");
			}
			return borrowed.genGoto(fall);
		}

		@Override
		public StringTree genGoto(RVal cond, Label fall) {
			if (this == fall) { // placed with also check
				return StringTree.single("");
			}
			return borrowed.genGoto(cond, fall);
		}
	}

	/**
	 * The virtual fall-through label
	 * 
	 * <p>
	 * The idea is that no one should ever need to generate labels or gotos to achieve fall-through.
	 * Any attempt to do so probably indicates an implementation error where code generation failed
	 * to place a label.
	 */
	private final class FallLabel implements Label {
		@Override
		public Label freshOrBorrow() {
			return new FreshLabel();
		}

		@Override
		public StringTree genAnchor() {
			return StringTree.single("");
		}

		@Override
		public StringTree ref() {
			throw new AssertionError();
		}

		@Override
		public StringTree genGoto(Label fall) {
			return StringTree.single("");
		}

		@Override
		public StringTree genGoto(RVal cond, Label fall) {
			throw new AssertionError();
		}
	}

	/**
	 * The singleton instance of the fall-through "label."
	 */
	protected final Label FALL = new FallLabel();

	// Used only for variable name validation
	final PcodeParser parser;
	final SleighLanguage language;
	private final Factory factory;

	private BlockStmt root;
	// Used to determine statement binding, e.g., for "_break" and "_result"
	final Deque<BlockStmt> stack = new LinkedList<>();
	// Collects data types used in annotations and during code generation
	final StandAloneDataTypeManager dtm;
	private final List<DataTypeParser> dtSources = new ArrayList<>();

	// The next "free" label
	private int nextLabel = 1;
	// The next "free" temp variable
	private int nextTemp = 1;

	/** A variable to use for unwanted results */
	DefaultVar nil;

	/**
	 * Bind this Structured Sleigh context to the given program's language, compiler spec, and data
	 * type manager.
	 * 
	 * @param program the program
	 */
	protected StructuredSleigh(Program program) {
		this(program.getCompilerSpec());
		addDataTypeSource(program.getDataTypeManager());
	}

	/**
	 * Bind this Structured Sleigh context to the given compiler spec using only built-in types
	 * 
	 * @param cs the compiler spec
	 */
	protected StructuredSleigh(CompilerSpec cs) {
		this.language = (SleighLanguage) cs.getLanguage();
		this.parser = SleighProgramCompiler.createParser(language);
		this.factory = new Factory(language);
		this.dtm = new StandAloneDataTypeManager("/", cs.getDataOrganization());

		addDataTypeSource(dtm);
		addDataTypeSource(BuiltInDataTypeManager.getDataTypeManager());

		this.nil = new DefaultVar(this, Check.NONE, SleighProgramCompiler.NIL_SYMBOL_NAME,
			DefaultDataType.dataType);
	}

	/**
	 * Add another data type manager as a possible source of data types
	 * 
	 * @see #type(String)
	 * @param source the additional data type manager
	 */
	protected void addDataTypeSource(DataTypeManager source) {
		dtSources.add(new DataTypeParser(source, dtm, null, AllowedDataTypes.ALL));
	}

	/**
	 * Add several data type managers as source of data types
	 * 
	 * @see #type(String)
	 * @param sources the additional managers
	 */
	protected void addDataTypeSources(Collection<DataTypeManager> sources) {
		for (DataTypeManager src : sources) {
			addDataTypeSource(src);
		}
	}

	/**
	 * Import a variable defined by the processor language
	 * 
	 * @param name the name of the variable. The name must already be defined by the processor
	 * @param type the type of the variable
	 * @return a handle to the variable
	 */
	protected Var lang(String name, DataType type) {
		LangVar lang = new LangVar(this, name, type);
		return lang;
	}

	/**
	 * Import a register variable
	 * 
	 * @param register the register
	 * @param type the type of the variable
	 * @return a handle to the variable
	 */
	protected Var reg(Register register, DataType type) {
		return lang(register.getName(), type);
	}

	/**
	 * Internal use only: Create a handle to a parameter
	 * 
	 * @param name the name of the parameter
	 * @param type the type of the parameter
	 * @return a handle to the variable
	 */
	private Var param(String name, DataType type) {
		return new LocalVar(this, name, type);
	}

	/**
	 * Declare a local variable with the given name and type
	 * 
	 * <p>
	 * If the variable has no definitive type, but has a known size, use e.g.,
	 * {@link Undefined8DataType} or {@link #type(String)} with "{@code /undefined8}". If the
	 * variable's size depends on the ABI, use the most appropriate integer or pointer type, e.g.,
	 * "{@code /void*}".
	 * 
	 * @param name the name of the variable. The name cannot already be defined by the processor
	 * @param type the type of the variable
	 * @return a handle to the variable
	 */
	protected Var local(String name, DataType type) {
		LocalVar local = new LocalVar(this, name, type);
		new DeclStmt(this, local);
		return local;
	}

	/**
	 * Declare a local variable with the given name and initial value
	 * 
	 * <p>
	 * The type is taken from that of the initial value.
	 * 
	 * @param name the name of the variable. The name cannot already be defined by the processor
	 * @param init the initial value (and type)
	 * @return a handle to the variable
	 */
	protected Var local(String name, RVal init) {
		Var temp = new LocalVar(this, name, init.getType());
		new AssignStmt(this, temp, init);
		return temp;
	}

	/**
	 * Allocate a temporary local variable of the given type
	 * 
	 * @param type the type
	 * @return a handle to the variable
	 */
	protected Var temp(DataType type) {
		return local("__temp" + (nextTemp++), type);
	}

	/**
	 * Get a type from a bound data type manager by path
	 * 
	 * @param path the full path to the data type, including leading "/"
	 * @return the data type
	 * @throws StructuredSleighError if the type cannot be found
	 */
	protected DataType type(String path) {
		for (DataTypeParser source : dtSources) {
			DataType type;
			try {
				type = source.parse(path);
			}
			catch (InvalidDataTypeException e) {
				continue;
			}
			catch (CancelledException e) {
				throw new AssertionError(e);
			}
			if (type != null) {
				return type;
			}
		}
		throw new StructuredSleighError("No such type: " + path);
	}

	/**
	 * Get several types
	 * 
	 * @see #type(String)
	 * @param paths the data types paths
	 * @return the data types in the same order
	 * @throws StructuredSleighError if any type cannot be found
	 */
	protected List<DataType> types(String... paths) {
		return Stream.of(paths).map(this::type).collect(Collectors.toList());
	}

	/**
	 * Declare an external userop
	 * 
	 * @param returnType the userop's "return type"
	 * @param name the name of the userop as it would appear in Sleigh code
	 * @param parameterTypes the types of its parameters, in order
	 * @return the declaration, suitable for generating invocations
	 */
	protected UseropDecl userop(DataType returnType, String name, List<DataType> parameterTypes) {
		return new DefaultUseropDecl(this, returnType, name, parameterTypes);
	}

	/**
	 * Generate a literal (or immediate or constant) value
	 * 
	 * <p>
	 * <b>WARNING:</b> Passing a literal int that turns out to be negative (easy to do in hex
	 * notation) can be perilous. For example, 0xdeadbeef will actually result in 0xffffffffdeadbeef
	 * because Java will cast it to a long before it's passed into this method. Use 0xdeadbeefL
	 * instead.
	 * 
	 * @param val the value
	 * @param size the size of the value in bytes
	 * @return a handle to the value
	 */
	protected RVal lit(long val, int size) {
		return new LiteralLongExpr(this, val, size);
	}

	/**
	 * Generate a literal (or immediate or constant) single-precision floating-point value
	 * 
	 * @param val the value
	 * @return a handle to the value
	 */
	protected RVal litf(float val) {
		return litf(val, FloatDataType.dataType);
	}

	/**
	 * Generate a literal (or immediate or constant) double-precision floating-point value
	 * 
	 * @param val
	 * @return a handle to the value
	 */
	protected RVal litd(double val) {
		return litf(val, DoubleDataType.dataType);
	}

	/**
	 * Generate a literal (or immediate or constant) floating-point value
	 * 
	 * @param val
	 * @param type the type of the value
	 * @return a handle to the value
	 */
	protected RVal litf(double val, DataType type) {
		return new LiteralFloatExpr(this, val, type);
	}

	/**
	 * Generate Sleigh code
	 * 
	 * <p>
	 * This is similar in concept to inline assembly. It allows the embedding of Sleigh code into
	 * Structured Sleigh that is otherwise impossible or inconvenient to state. No effort is made to
	 * ensure the correctness of the given Sleigh code nor its impact in context.
	 * 
	 * @param rawStmt the Sleigh code
	 * @return a handle to the statement
	 */
	public Stmt s(String rawStmt) {
		return new RawStmt(this, rawStmt);
	}

	/**
	 * Generate a Sleigh expression
	 * 
	 * <p>
	 * This is similar in concept to inline assembly, except it also has a value. It allows the
	 * embedding of Sleigh code into Structured Sleigh that is otherwise impossible or inconvenient
	 * to express. No effort is made to ensure the correctness of the given Sleigh expression nor
	 * its impact in context. The result is assigned a type of "void".
	 * 
	 * @param rawExpr the Sleigh expression
	 * @return a handle to the value
	 */
	public Expr e(String rawExpr) {
		return new RawExpr(this, rawExpr);
	}

	/**
	 * The wrapper around an {@link StructuredSleigh#_if(RVal, Runnable)} statement providing
	 * additional DSL syntax
	 */
	public class WrapIf {
		private final IfStmt _if;

		protected WrapIf(IfStmt _if) {
			this._if = _if;
		}

		/**
		 * Generate an "else" clause for the wrapped "if" statement
		 * 
		 * @param body the body of the clause
		 */
		public void _else(Runnable body) {
			_if.addElse(new BlockStmt(StructuredSleigh.this, body));
		}

		/**
		 * Generate an "else if" clause for the wrapped "if" statement
		 * 
		 * <p>
		 * This is shorthand for {@code _else(_if(...))} but avoids the unnecessary nesting of
		 * parentheses.
		 * 
		 * @param cond the condition
		 * @param body the body of the clause
		 * @return a wrapper to the second "if" statement
		 */
		public WrapIf _elif(Expr cond, Runnable body) {
			IfStmt _elif = doIf(cond, body);
			_if.addElse(_elif);
			return new WrapIf(_elif);
		}
	}

	private IfStmt doIf(RVal cond, Runnable body) {
		return new IfStmt(this, cond, new BlockStmt(this, body));
	}

	/**
	 * Generate an "if" statement
	 * 
	 * <p>
	 * The body is usually a lambda containing additional statements, predicated on this statement's
	 * condition, so that it resembles Java / C syntax:
	 * 
	 * <pre>
	 * _if(r0.eq(4), () -> {
	 * 	r1.set(1);
	 * });
	 * </pre>
	 * 
	 * <p>
	 * The returned "wrapper" provides for additional follow-on syntax, e.g.:
	 * 
	 * <pre>
	 * _if(r0.eq(4), () -> {
	 * 	r1.set(1);
	 * })._elif(r0.eq(5), () -> {
	 * 	r1.set(3);
	 * })._else(() -> {
	 * 	r1.set(r0.muli(2));
	 * });
	 * </pre>
	 * 
	 * @param cond the condition
	 * @param body the body of the statement
	 * @return a wrapper to the generated "if" statement
	 */
	protected WrapIf _if(RVal cond, Runnable body) {
		return new WrapIf(doIf(cond, body));
	}

	/**
	 * Generate a "while" statement
	 * 
	 * <p>
	 * The body is usually a lambda containing the controlled statements, so that it resembles Java
	 * / C syntax:
	 * 
	 * <pre>
	 * Var temp = local("temp", "/int");
	 * _while(temp.ltiu(10), () -> {
	 * 	temp.inc();
	 * });
	 * </pre>
	 * 
	 * @param cond the condition
	 * @param body the body of the loop
	 */
	protected void _while(RVal cond, Runnable body) {
		new WhileStmt(this, cond, new BlockStmt(this, body));
	}

	/**
	 * Generate a "for" statement
	 * 
	 * <p>
	 * The body is usually a lambda containing the controlled statements, so that it resembles Java
	 * / C syntax:
	 * 
	 * <pre>
	 * Var temp = local("temp", "/int");
	 * Var total = local("total", "/int");
	 * total.set(0);
	 * _for(temp.set(0), temp.ltiu(10), temp.inc(1), () -> {
	 * 	total.addiTo(temp);
	 * });
	 * </pre>
	 * 
	 * <p>
	 * TIP: If the number of repetitions is known at generation time, consider using a standard Java
	 * for loop, as a sort of Structured Sleigh macro. For example, to broadcast element 0 to an
	 * in-memory 16-long vector pointed to by r0:
	 * 
	 * <pre>
	 * Var arr = lang("r0", "/int *");
	 * for (int i = 1; i < 16; i++) {
	 * 	arr.index(i).deref().set(arr.index(0).deref());
	 * }
	 * </pre>
	 * 
	 * <p>
	 * Instead of generating a loop, this will generate 15 Sleigh statements.
	 * 
	 * @param init the loop initializer
	 * @param cond the loop condition
	 * @param step the loop stepper
	 * @param body the body of the loop
	 */
	protected void _for(Stmt init, RVal cond, Stmt step, Runnable body) {
		new ForStmt(this, init, cond, step, new BlockStmt(this, body));
	}

	/**
	 * Generate a "break" statement
	 * 
	 * <p>
	 * This must appear in the body of a loop statement. It binds to the innermost loop statement in
	 * which it appears, generating code to leave that loop.
	 */
	protected void _break() {
		new BreakStmt(this);
	}

	/**
	 * Generate a "continue" statement
	 * 
	 * <p>
	 * This must appear in the body of a loop statement. It binds to the innermost loop statement in
	 * which it appears, generating code to immediately repeat the loop, skipping the remainder of
	 * its body.
	 */
	protected void _continue() {
		new ContinueStmt(this);
	}

	/**
	 * Generate a "result" statement
	 * 
	 * <p>
	 * This is semantically similar to a C "return" statement, but is named differently to avoid
	 * confusion with Sleigh's return statement. When this is code implementing a p-code userop,
	 * this immediately exits the userop, returning control to the caller where the invocation takes
	 * the value given in this statement.
	 * 
	 * <p>
	 * Contrast with {@link #_return(RVal)}
	 * 
	 * @param result the resulting value of the userop
	 */
	protected void _result(RVal result) {
		new ResultStmt(this, result);
	}

	/**
	 * Generate a "return" statement
	 * 
	 * <p>
	 * This models (in part) a C-style return from the current target function to its caller. It
	 * simply generates the "return" Sleigh statement, which is an indirect branch to the given
	 * target. Target is typically popped from the stack or read from a link register.
	 * 
	 * <p>
	 * Contrast with {@link #_result(RVal)}
	 * 
	 * @param target the offset of the target
	 */
	protected void _return(RVal target) {
		new ReturnStmt(this, target);
	}

	/**
	 * Generate a "goto" statement to another address in the processor's code space
	 * 
	 * @param target the offset of the target address
	 */
	protected void _goto(RVal target) {
		new GotoStmt(this, target);
	}

	/**
	 * Get the method lookup for this context
	 * 
	 * <p>
	 * If the annotated methods cannot be accessed by {@link StructuredSleigh}, this method must be
	 * overridden. It should simply return {@link MethodHandles#lookup()}. This is necessary when
	 * the author chooses access modifiers other than {@code public}, which is good practice, or
	 * when the class is an anonymous inner class, as is often the case with stand-alone use.
	 * 
	 * @return the lookup
	 */
	protected Lookup getMethodLookup() {
		return MethodHandles.lookup();
	}

	private <T> SleighPcodeUseropDefinition<T> compile(StructuredUserop annot, Lookup lookup,
			Method method) {
		if (annot == null) {
			throw new IllegalArgumentException("Method " + method + " is missing @" +
				StructuredUserop.class.getSimpleName() + " annotation.");
		}
		if (method.getReturnType() != void.class) {
			throw new IllegalArgumentException("Method " + method + " having @" +
				StructuredUserop.class.getSimpleName() + " annotation must return void.");
		}
		MethodHandle handle;
		try {
			handle = lookup.unreflect(method).bindTo(this);
		}
		catch (IllegalAccessException e) {
			throw new IllegalArgumentException("Cannot access " + method + " having @" +
				StructuredUserop.class.getSimpleName() + " annotation. Override getMethodLookup()");
		}
		Builder builder = factory.define(method.getName());

		DataType retType = type(annot.type());

		Parameter[] params = method.getParameters();
		@SuppressWarnings("unchecked")
		List<Entry<String, DataType>> paramsAndTypes = Arrays.asList(new Entry[params.length]);
		for (int i = 0; i < params.length; i++) {
			Parameter p = params[i];
			if (p.getType() != Var.class) {
				throw new IllegalArgumentException(
					"Parameter " + p + " of method " + method + " must have type Var.");
			}
			Param pAnnot = p.getAnnotation(Param.class);
			if (pAnnot == null) {
				throw new StructuredSleighError("No @" + Param.class.getSimpleName() +
					" annotation of parameter " + p + " of method " + method + ".");
			}
			String name = "".equals(pAnnot.name()) ? p.getName() : pAnnot.name();
			DataType type = type(pAnnot.type());
			paramsAndTypes.set(i, Map.entry(name, type));
		}
		builder.params(paramsAndTypes.stream().map(p -> p.getKey()).collect(Collectors.toList()));

		assert stack.isEmpty();
		root = new RoutineStmt(this, method.getName(), retType, () -> {
			List<Object> args = paramsAndTypes.stream()
					.map(p -> param(p.getKey(), p.getValue()))
					.collect(Collectors.toList());
			try {
				handle.invokeWithArguments(args);
			}
			catch (StructuredSleighError e) {
				throw e;
			}
			catch (Throwable e) {
				throw new StructuredSleighError(
					"Exception processing structured sleigh body",
					e);
			}
		});
		StringTree source = root.generate(FALL, FALL);
		builder.body(source.toString());
		return builder.build();
	}

	/**
	 * Generate all the exported userops and place them into the given map
	 * 
	 * @param <T> the type of values used by the userops. For sleigh, this can be anything.
	 * @param into the destination map, usually belonging to a {@link PcodeUseropLibrary}.
	 */
	public <T> void generate(Map<String, ? super SleighPcodeUseropDefinition<T>> into) {
		Lookup lookup = getMethodLookup();
		Class<? extends StructuredSleigh> cls = this.getClass();
		Set<Method> methods =
			CACHE_BY_CLASS.computeIfAbsent(cls, __ -> collectDefinitions(cls));
		for (Method m : methods) {
			into.put(m.getName(), doGenerate(lookup, m));
		}
	}

	/**
	 * Generate the userop for a given Java method
	 * 
	 * @param <T> the type of values used by the userop. For sleigh, this can be anything.
	 * @param m the method exported as a userop
	 * @return the userop
	 */
	public <T> SleighPcodeUseropDefinition<T> generate(Method m) {
		return doGenerate(getMethodLookup(), m);
	}

	protected <T> SleighPcodeUseropDefinition<T> doGenerate(Lookup lookup, Method m) {
		return compile(m.getAnnotation(StructuredUserop.class), lookup, m);
	}

	/**
	 * Generate all the exported userops and return them in a map
	 * 
	 * <p>
	 * This is typically only used when not part of a larger {@link PcodeUseropLibrary}, for example
	 * to aid in developing a Sleigh module or for generating injects.
	 * 
	 * @param <T> the type of values used by the userop. For sleigh, this can be anything.
	 * @return the userop
	 */
	public <T> Map<String, SleighPcodeUseropDefinition<T>> generate() {
		Map<String, SleighPcodeUseropDefinition<T>> ops = new HashMap<>();
		generate(ops);
		return ops;
	}

	/**
	 * Validate and compute the size (in bytes) of a floating-point data type
	 * 
	 * @param type the type
	 * @return the size of the type
	 */
	protected int computeFloatSize(DataType type) {
		if (!(type instanceof AbstractFloatDataType)) {
			throw new StructuredSleighError("Must be a floating-point type. Got " + type);
		}
		return type.getLength();
	}

	/**
	 * Encode a floating-point value
	 * 
	 * @param val the value
	 * @param size the size (in bytes)
	 * @return the encoded bits
	 */
	protected long encodeFloat(double val, int size) {
		return FloatFormatFactory.getFloatFormat(size).getEncoding(val);
	}

	/**
	 * Extension point: Specify whether values of a given type can be assigned to variables of
	 * another type
	 * 
	 * <p>
	 * The default is to check if the types are equivalent: {@link DataType#isEquivalent(DataType)}.
	 * 
	 * @param varType the variable's data type (assign to)
	 * @param valType the value's data type (assign from)
	 * @return true if allowed, false otherwise
	 */
	protected boolean isAssignable(DataType varType, DataType valType) {
		// TODO: isEquivalent is not quite it
		return varType.isEquivalent(valType);
	}

	/**
	 * Extension point: Specify how to handle a type mismatch in an assignment
	 * 
	 * <p>
	 * The default is to log a warning and continue.
	 * 
	 * @param lhs the variable being assigned
	 * @param rhs the value being assigned to the variable
	 */
	protected void emitAssignmentTypeMismatch(LVal lhs, RVal rhs) {
		Msg.warn(this, "Type mismatch in assignment: " + lhs + " = " + rhs);
	}

	/**
	 * Extension point: Specify how to handle a parameter to argument count mismatch
	 * 
	 * <p>
	 * The default is to throw an unrecoverable error. If allowed to continue, the matched
	 * parameters are type checked and the invocation generated as specified. Most likely, the
	 * emulator will crash while executing the invoked userop.
	 * 
	 * @param userop the userop being called
	 * @param arguments the arguments being passed
	 */
	protected void emitParameterCountMismatch(UseropDecl userop, List<RVal> arguments) {
		throw new StructuredSleighError(
			"Parameter/argument count mismatch invoking " + userop.getName() + ": Expected " +
				userop.getParameterTypes().size() + " but got " + arguments.size());
	}

	/**
	 * Extension point: Specify how to handle a parameter type mismatch
	 * 
	 * <p>
	 * The default is to log a warning and continue.
	 * 
	 * @param userop the userop being called
	 * @param position the position of the parameter
	 * @param value the value being assigned
	 */
	protected void emitParameterTypeMismatch(UseropDecl userop, int position, RVal value) {
		Msg.warn(this, "Type mismatch for parameter " + position + " of " + userop.getName() +
			": " + value + " is not a " + userop.getParameterTypes().get(position));
	}

	/**
	 * Extension point: Specify how to handle a result type mismatch
	 * 
	 * <p>
	 * The default is to log a warning and continue.
	 * 
	 * @param routine the routine (userop) containing the result statement
	 * @param result the result value specified in the statement
	 */
	protected void emitResultTypeMismatch(RoutineStmt routine, RVal result) {
		Msg.warn(this, "Type mismatch on result of " + routine.name + ": " + result + " is not a " +
			routine.retType);
	}

	/**
	 * Compute the type of a dereferenced address
	 * 
	 * @param addr the value of the pointer
	 * @return the resulting type
	 */
	protected DataType computeDerefType(RVal addr) {
		DataType addrType = addr.getType();
		if (addrType instanceof Pointer) {
			Pointer pointer = (Pointer) addrType;
			return pointer.getDataType();
		}
		emitDerefNonPointer(addr);
		return VoidDataType.dataType;
	}

	/**
	 * Extension point: Specify how to handle dereference of a non-pointer value
	 * 
	 * <p>
	 * The default is to log a warning and continue. If permitted to continue, the resulting type
	 * will be {@code void}, likely resulting in more issues. See
	 * {@link #computeDerefType(DataType)}.
	 * 
	 * @param addr the value being dereferenced
	 */
	protected void emitDerefNonPointer(RVal addr) {
		Msg.warn(this, "Dereference requires pointer type. Got " + addr);
	}

	/**
	 * Compute the length (in bytes) of an element of a pointer to an array
	 * 
	 * @param addr the value of the pointer
	 * @return the length of one element
	 */
	protected int computeElementLength(RVal addr) {
		DataType pType = addr.getType();
		if (!(pType instanceof Pointer)) {
			throw new StructuredSleighError("Index requires pointer type. Got " + addr);
		}
		DataType eType = ((Pointer) pType).getDataType();
		return eType.getLength();
	}

	/**
	 * Find the type component (field) of a pointer to a composite type
	 * 
	 * <p>
	 * In terms of type manipulation, this is equivalent the C expression {@code addr->field}.
	 * {@link LVal#field(String)} uses the component to derive the offset and the resulting pointer
	 * type.
	 * 
	 * @param addr the value of the pointer
	 * @param name the field being accessed
	 * @return the found component
	 * 
	 * @throws StructuredSleighError if the field cannot be found
	 */
	protected DataTypeComponent findComponent(RVal addr, String name) {
		DataType aType = addr.getType();
		if (!(aType instanceof Pointer)) {
			throw new StructuredSleighError(
				"Offset requires pointer to composite type. Got " + addr);
		}
		DataType rType = ((Pointer) aType).getDataType();
		if (!(rType instanceof Composite)) {
			throw new StructuredSleighError(
				"Cannot access field of non-Composite pointer " + addr);
		}
		Composite composite = (Composite) rType;
		DataTypeComponent dtc = findComponentByName(composite, name);
		if (dtc == null) {
			throw new StructuredSleighError("No such field '" + name + "' of " + addr);
		}
		if (dtc.isBitFieldComponent()) {
			throw new StructuredSleighError(
				"Bitfield types are not yet supported: '" + dtc + "' of " + addr);
		}
		return dtc;
	}
}
