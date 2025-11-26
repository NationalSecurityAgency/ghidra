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
package ghidra.app.util.bin.format.objc;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.task.TaskMonitor;

/**
 * Implemented by all Objective-C type metadata structures
 */
public abstract class ObjcTypeMetadataStructure implements StructConverter {

	public static final String DATA_TYPE_CATEGORY = "/ObjcTypeMetadata";

	protected Program program;
	protected ObjcState state;
	protected long base;
	protected int pointerSize;
	protected boolean is32bit;
	protected boolean isArm;

	public ObjcTypeMetadataStructure(Program program, ObjcState state, long base) {
		this.program = program;
		this.state = state;
		this.base = base;
		this.pointerSize = program.getDefaultPointerSize();
		this.is32bit = pointerSize == 4;
		this.isArm = program.getLanguage()
				.getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor("ARM"));
	}

	/**
	 * {@return the {@link Program} associated with this {@link ObjcTypeMetadataStructure}}
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * {@return the base "address" of this {@link ObjcTypeMetadataStructure}}
	 */
	public long getBase() {
		return base;
	}

	/**
	 * {@return the {@link ObjcState state} of this {@link ObjcTypeMetadataStructure}}
	 */
	public ObjcState getState() {
		return state;
	}

	/**
	 * {@return the generic pointer size used by this {@link ObjcTypeMetadataStructure}}
	 */
	public int getPointerSize() {
		return pointerSize;
	}

	/**
	 * {@return whether or not the pointer size is 32-bit}
	 */
	public boolean is32bit() {
		return is32bit;
	}

	/**
	 * {@return whether or not this {@link ObjcTypeMetadataStructure} is for the ARM-processor}
	 */
	public boolean isArm() {
		return isArm;
	}

	/**
	 * Applies this {@link ObjcTypeMetadataStructure} to the program
	 * 
	 * @param namespace An optional {@link Namespace} to apply to
	 * @param monitor A cancellable monitor
	 * @throws Exception if an error occurred
	 */
	public abstract void applyTo(Namespace namespace, TaskMonitor monitor) throws Exception;
}
