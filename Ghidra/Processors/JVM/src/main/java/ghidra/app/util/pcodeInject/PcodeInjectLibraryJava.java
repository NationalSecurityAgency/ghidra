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
package ghidra.app.util.pcodeInject;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.jdom.JDOMException;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.template.OpTpl;
import ghidra.pcodeCPort.slgh_compile.PcodeParser;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;

/**
 * 
 * This class handles dynamic pcode injection for modeling JVM bytecode.
 * 
 * There are some notable differences between a java .class file and an executable compiled for
 * a physical processor, which present some complications when modeling bytecode with pcode.
 * Some of the bigger differences are:
 *   1) The java compiler does not know the runtime layout of a class - that's up to the JVM implementer
 *      to decide.  Methods and fields of a class are accessed by name in a .class file - there are no
 *      vtables or field offsets in bytecode.  
 *   2) Each method gets its own area in memory called a method stack.  It is not assumed to be contiguous
 *      with other method stacks.  There is no concept of the address of a method. 
 *   3) Parameters are passed to a method on the operand stack in left to right order (first parameter pushed first).
 *      However, within a method body, parameters to that method are not read from the operand stack.  Instead,
 *      they are read from an area known as the "local variable array".  
 *   4) Many bytecode operations reference the constant pool.  For example, some of the bytes of an invoke 
 *      instruction encode an index in the constant pool.  By reading data at that index, you can determine
 *      the signature, name, and class of the method to be invoked.  
 *   5) In some instances, you must consult the constant pool to determine how an instruction changes the
 *      the stack.  For instance, a getfield operation can push either 4 or 8 bytes on to the stack, 
 *      depending on the "computational category" of the field (object references, integers, and floats are 
 *      4 bytes, longs and doubles are 8).  You cannot determine the computational category from the bytes 
 *      of the instruction, you must examine the element at the encoded index into the constant pool. 
 * 
 * The file JVM.slaspec contains definitions of fake registers which are not part of the JVM specification
 * but are necessary to model class files in pcode.  These registers include return_value, cat2_return_value,
 * switch_target, return_address
 * 
 * defined pcodeop naming schemes:
 *   ops ending in "CallOther" are used for pcode injection
 *   ops ending in "Op" are used as black-box ops.  
 * 
 * How to implement pcode injection for an operation "testop":
 * JVM.pspec:
 *   ensure that the processor spec properties includes:
 *      <property key="pcodeInjectLibraryClass" value="ghidra.app.util.pcodeInject.PcodeInjectLibraryJava"/>
 *   (this property needs to be there for injection to work.  It's included as a step here for
 *    general pcode injection documentation.  In the general case, modify the value as appropriate.)
 * JVM.slaspec: 
 *   define a new pcodeop testopCallOther
 *   define a new pcodeop testopOp, if necessary (if you need a black-box operation to model testop) 
 *   in the pcode for testop, emit a call to testopCallOther.
 * JVM.cspec:
 *   define a callotherfixup targetop "testopCallOther" - see the other callotherfixups
 * PcodeInectLibrary.java:
 *   define a constant string "testopCallOther"
 *   in the constructor for this class, add the newly-defined string to the set implementedOps 
 *   add a case statement restorePcodeXml
 * Create a subclass of InjectPayloadJava to generate/compile pcode
 *   (Use/add to PcodeTextEmitter.java to actually emit pcode text)
 * See ConstantPoolJava.java for examples of the use of the CPOOL pcode op.
 * 
  * possible improvements:
 *
 *   2) incorporate exceptions.
 *   6) decide how to display the information used in an invokedynamic instruction
 *   7) jsr/ret instructions are not modeled using pcode injection.  The jsr (jump to subroutine) 
 *      instruction is deprecated and can't appear in class files with version >= 51.0.  This is a 
 *      strange instruction which pushes the address of the following instruction onto the operand
 *      stack and then jumps to a subroutine.  The subroutine ends with a ret instruction, which
 *      retrieves the address from a local variable (not from the stack).  The JVM handles moving
 *      the address from the stack to the local variable.  In order to model this, you would need
 *      to determine which ret instruction is paired with a jsr instruction and inject pcode to move
 *      the address into the local variable that the ret instruction reads from.  You will need to
 *      follow flow from the beginning of the subroutine the corresponding ret instruction(s?).
 *     
 */

public class PcodeInjectLibraryJava extends PcodeInjectLibrary {

	public static final int CONSTANT_POOL_START_ADDRESS = 0xa;

	//names of defined pcode ops that require pcode injection
	public static final String GETFIELD = "getFieldCallOther";
	public static final String GETSTATIC = "getStaticCallOther";
	public static final String INVOKE_DYNAMIC = "invokedynamicCallOther";
	public static final String INVOKE_INTERFACE = "invokeinterfaceCallOther";
	public static final String INVOKE_SPECIAL = "invokespecialCallOther";
	public static final String INVOKE_STATIC = "invokestaticCallOther";
	public static final String INVOKE_VIRTUAL = "invokevirtualCallOther";
	public static final String LDC = "ldcCallOther";
	public static final String LDC2_W = "ldc2_wCallOther";
	public static final String LDC_W = "ldc_wCallOther";
	public static final String MULTIANEWARRAY = "multianewarrayCallOther";

	public static final String PUTFIELD = "putFieldCallOther";
	public static final String PUTSTATIC = "putStaticCallOther";

	//size of one stack element in the jvm (in bytes)
	public static final int REFERENCE_SIZE = 4;

	private SleighLanguage language;
	private Set<String> implementedOps;
	private PcodeParser parser;
	private InjectPayloadJavaParameters paramPayload;

	public PcodeInjectLibraryJava(SleighLanguage l) {
		super(l);
		language = l;
		implementedOps = new HashSet<>();
		implementedOps.add(GETFIELD);
		implementedOps.add(GETSTATIC);
		implementedOps.add(INVOKE_DYNAMIC);
		implementedOps.add(INVOKE_INTERFACE);
		implementedOps.add(INVOKE_SPECIAL);
		implementedOps.add(INVOKE_STATIC);
		implementedOps.add(INVOKE_VIRTUAL);
		implementedOps.add(LDC);
		implementedOps.add(LDC2_W);
		implementedOps.add(LDC_W);
		implementedOps.add(MULTIANEWARRAY);
		implementedOps.add(PUTFIELD);
		implementedOps.add(PUTSTATIC);

		String translateSpec = language.buildTranslatorTag(language.getAddressFactory(),
			getUniqueBase(), language.getSymbolTable());

		paramPayload = null;
		parser = null;
		try {
			parser = new PcodeParser(translateSpec);
		}
		catch (JDOMException e1) {
			e1.printStackTrace();
		}
	}

	@Override
	protected InjectPayloadSleigh allocateInject(String sourceName, String name, int tp) {
		InjectPayloadJava payload = null;
		if (tp != InjectPayload.CALLOTHERFIXUP_TYPE) {
			return super.allocateInject(sourceName, name, tp);
		}
		switch (name) {
			case GETFIELD:
				payload = new InjectGetField(sourceName, language);
				break;
			case GETSTATIC:
				payload = new InjectGetStatic(sourceName, language);
				break;
			case INVOKE_DYNAMIC:
				payload = new InjectInvokeDynamic(sourceName, language);
				break;
			case INVOKE_INTERFACE:
				payload = new InjectInvokeInterface(sourceName, language);
				break;
			case INVOKE_SPECIAL:
				payload = new InjectInvokeSpecial(sourceName, language);
				break;
			case INVOKE_STATIC:
				payload = new InjectInvokeStatic(sourceName, language);
				break;
			case INVOKE_VIRTUAL:
				payload = new InjectInvokeVirtual(sourceName, language);
				break;
			case LDC:
			case LDC2_W:
			case LDC_W:
				payload = new InjectLdc(sourceName, language);
				break;
			case MULTIANEWARRAY:
				payload = new InjectMultiANewArray(sourceName, language);
				break;
			case PUTFIELD:
				payload = new InjectPutField(sourceName, language);
				break;
			case PUTSTATIC:
				payload = new InjectPutStatic(sourceName, language);
				break;
			default:
				return super.allocateInject(sourceName, name, InjectPayload.CALLOTHERFIXUP_TYPE);
		}
		return payload;
	}

	@Override
	/**
	* This method is called by DecompileCallback.getPcodeInject.
	*/
	public InjectPayload getPayload(int type, String name, Program program, String context) {
		if (type == InjectPayload.CALLMECHANISM_TYPE) {
			if (paramPayload == null) {
				paramPayload = new InjectPayloadJavaParameters();
			}
			return paramPayload;
		}

		if (!implementedOps.contains(name)) {
			return super.getPayload(type, name, program, context);
		}

		InjectPayloadJava payload =
			(InjectPayloadJava) super.getPayload(InjectPayload.CALLOTHERFIXUP_TYPE, name, program,
				context);

		synchronized (parser) {
			OpTpl[] opTemplates = payload.getPcode(parser, program, context);
			adjustUniqueBase(opTemplates);
			//clear the added symbols so that the parser can be used again without
			//duplicate symbol name conflicts.
			parser.clearSymbols();
		}
		return payload;
	}

	@Override
	public ConstantPool getConstantPool(Program program) throws IOException {
		return new ConstantPoolJava(program);
	}

}
