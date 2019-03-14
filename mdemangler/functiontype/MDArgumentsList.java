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
package mdemangler.functiontype;

import java.util.ArrayList;
import java.util.List;

import mdemangler.*;
import mdemangler.datatype.*;
import mdemangler.datatype.complex.MDComplexType;
import mdemangler.datatype.extended.MDExtendedType;
import mdemangler.datatype.modifier.MDModifierType;

/**
 * This class represents an arguments list of a function within a Microsoft mangled symbol.
 */
public class MDArgumentsList extends MDParsableItem {
	private List<MDDataType> args = new ArrayList<>();

	public MDArgumentsList(MDMang dmang) {
		super(dmang);
	}

	public int getNumArgs() {
		return args.size();
	}

	public MDDataType getArg(int index) {
		return args.get(index);
	}

	@Override
	protected void parseInternal() throws MDException {
		boolean argsDone = false;
		while (!argsDone) {
			char code = dmang.peek();
			MDDataType dt;
			switch (code) {
				case '@':
					dmang.increment();
					argsDone = true;
					break;
				case 'X':
					dmang.increment();
					dt = new MDVoidDataType(dmang);
					dt.parse();
					// If "void" is first argument of a function, terminate the arguments list
					//  without an '@' list terminator.  A "void" can be found in other
					//  argument locations, freely, and they will not terminate the list.
					if (args.size() == 0) {
						argsDone = true;
					}
					args.add(dt);
					if (dmang.peek() == '@') {
						throw new MDException("Void list has '@' terminator");
					}
					// Do not put into backreference parameter list.
					break;
				case 'Z':
					dmang.increment();
					dt = new MDVarArgsType(dmang);
					dt.parse();
					args.add(dt);
					// Do not put into Backref parameter list.  Found counter example with
					//  backreference for an embedded function where, having made it a
					//  backreference, would have resulted in a wrong result.  20140523.
					argsDone = true;
					break;
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					dmang.increment();
					int index = code - '0';
					dt = dmang.getBackreferenceFunctionParameterMDDataType(index); // 20140610
					args.add(dt);
					break;
				case MDMang.DONE:
					throw new MDException("String Terminated");
				default:
					dt = MDDataTypeParser.parsePrimaryDataType(dmang, true);
					dt.parse();
					args.add(dt);
					if ((dt instanceof MDModifierType) || (dt instanceof MDExtendedType) ||
						(dt instanceof MDComplexType)) {
						dmang.addBackrefFunctionParameterMDDataType(dt);
					}
					break;
			}
		}
	}

	@Override
	public void insert(StringBuilder builder) {
		if (args.size() > 0) {
			Boolean firstArgDone = false;
			for (MDDataType arg : args) {
				if (firstArgDone) {
					dmang.appendString(builder, ",");
				}
				firstArgDone = true;
				StringBuilder argBuilder = new StringBuilder();
				arg.insert(argBuilder);
				dmang.appendString(builder, argBuilder.toString().trim());
				// doing toString() allows the Based5 "bug" to be cleaned per parameter.
				// possible:  dmang.appendString(builder, arg.toString().trim());
			}
		}
	}
}

/******************************************************************************/
/******************************************************************************/
