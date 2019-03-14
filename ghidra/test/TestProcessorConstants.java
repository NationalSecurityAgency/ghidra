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
package ghidra.test;

import ghidra.program.model.lang.Processor;

public class TestProcessorConstants {

	public static final Processor PROCESSOR_8051 = Processor.findOrPossiblyCreateProcessor("8051");
	/*Zilog*/
	public static final Processor PROCESSOR_Z80 = Processor.findOrPossiblyCreateProcessor("Z80");
	/*Motorola*/
	public static final Processor PROCESSOR_POWERPC =
		Processor.findOrPossiblyCreateProcessor("PowerPC");
	/*Sparc*/
	public static final Processor PROCESSOR_SPARC =
		Processor.findOrPossiblyCreateProcessor("Sparc");
	/*Intel */
	public static final Processor PROCESSOR_X86 = Processor.findOrPossiblyCreateProcessor("x86");
	/*TMS*/
	public static final Processor PROCESSOR_TMS320C3x =
		Processor.findOrPossiblyCreateProcessor("TMS320C3x");
	/*ARM*/
	public static final Processor PROCESSOR_ARM = Processor.findOrPossiblyCreateProcessor("ARM");
	/*DATA*/
	public static final Processor PROCESSOR_DATA = Processor.findOrPossiblyCreateProcessor("DATA");
}
