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
package ghidra.javaclass.format.attributes;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 *
 */
public class ExceptionHandlerJava implements StructConverter {
	private short startPC;
	private short endPC;
	private short handlerPC;
	private short catchType;

	public ExceptionHandlerJava(BinaryReader reader) throws IOException {
		startPC = reader.readNextShort();
		endPC = reader.readNextShort();
		handlerPC = reader.readNextShort();
		catchType = reader.readNextShort();
	}

	/**
	 * The values of the two items start_pc and end_pc indicate the ranges in the
	 * code array at which the exception handler is active. 
	 * <p>
	 * The value of start_pc must be a valid index into the code array 
	 * of the opcode of an instruction.
	 * <p>
	 * The value of start_pc must be less than the value of end_pc.
	 * <p>
	 * The start_pc is inclusive and end_pc is exclusive; that is, the exception
	 * handler must be active while the program counter is within the interval
	 * [start_pc, end_pc].
	 * @return a valid index into the code array
	 */
	public int getStartPC() {
		return startPC & 0xffff;
	}

	/**
	 * The values of the two items start_pc and end_pc indicate the ranges in the
	 * code array at which the exception handler is active.
	 * <p>
	 * The value of end_pc either must be a valid index into the code array of the
	 * opcode of an instruction or must be equal to code_length, the length of the
	 * code array.
	 * <p> 
	 * The value of start_pc must be less than the value of end_pc.
	 * <p>
	 * The start_pc is inclusive and end_pc is exclusive; that is, the exception
	 * handler must be active while the program counter is within the interval
	 * [start_pc, end_pc].  
	 * @return a valid index into the code array
	 */
	public int getEndPC() {
		return endPC & 0xffff;
	}

	/**
	 * The value of the handler_pc item indicates the start of the exception
	 * handler. The value of the item must be a valid index into the code array
	 * and must be the index of the opcode of an instruction.
	 * @return the start of the exception handler
	 */
	public int getHandlerPC() {
		return handlerPC & 0xffff;
	}

	/**
	 * If the value of the catch_type item is nonzero, it must be a valid index
	 * into the constant_pool table. The constant_pool entry at that index
	 * must be a CONSTANT_Class_info (?4.4.1) structure representing a class of
	 * exceptions that this exception handler is designated to catch. The exception
	 * handler will be called only if the thrown exception is an instance of the
	 * given class or one of its subclasses.
	 * <p>
	 * If the value of the catch_type item is zero, this exception handler is called
	 * for all exceptions. This is used to implement finally (?3.13).
	 * @return the value of the catch_type item
	 */
	public int getCatchType() {
		return catchType & 0xffff;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("exception_handler", 0);
		structure.add(WORD, "start_pc", null);
		structure.add(WORD, "end_pc", null);
		structure.add(WORD, "handler_pc", null);
		structure.add(WORD, "catch_type", null);
		return structure;
	}
}
