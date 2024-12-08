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
package mdemangler.naming;

import java.util.*;

import mdemangler.*;

/**
 * This class represents a namespace qualification.  It is composed of individual namespace
 * components (MDQualifier).
 */
public class MDQualification extends MDParsableItem implements Iterable<MDQualifier> {
	private List<MDQualifier> quals = new ArrayList<>();

	public MDQualification(MDMang dmang) {
		super(dmang);
	}

	public boolean hasContent() {
		return (quals.size() > 0);
	}

	@Override
	public void insert(StringBuilder builder) {
		// MDMANG SPECIALIZATION USED.
		dmang.insert(builder, this);
	}

	// TODO: Keep this and use for MD version of output down the road (perhaps both are placed
	//  into dispatcher model)
	public void insert_MdVersion(StringBuilder builder) {
		boolean isInterface = false;
		for (MDQualifier qual : quals) {
			// Results in brackets as follows:
			//   "Namespace[::InterfaceNameSpace]::BaseName"
			//   "InterfaceNamespace]::NameSpace::BaseName" --Note that MSFT does not include
			//     opening bracket here.
			if (isInterface) {
				dmang.insertString(builder, "[");
			}
			isInterface = qual.isInterface();
			if (isInterface) {
				dmang.insertString(builder, "]");
			}
			qual.insert(builder);
			if (quals.indexOf(qual) != (quals.size() - 1)) {
				dmang.insertString(builder, "::");
			}
		}
		if (isInterface) {
			dmang.insertString(builder, "[");
		}
	}

	// TODO: this is potential SPECIALIZATION for MDMangVS2015 (and others)
	public void insert_VSAll(StringBuilder builder) {
		boolean isInterface = false;
		for (MDQualifier qual : quals) {
			// Results in brackets as follows:
			//   "Namespace[::InterfaceNameSpace]::BaseName"
			//   "InterfaceNamespace]::NameSpace::BaseName" --Note that MSFT does not include
			//     opening bracket here.
			if (isInterface) {
				dmang.insertString(builder, "[");
			}
			isInterface = qual.isInterface();
			if (isInterface) {
				dmang.insertString(builder, "]");
			}
			qual.insert(builder);
			if (quals.indexOf(qual) != (quals.size() - 1)) {
				dmang.insertString(builder, "::");
			}
		}
	}

	public void insertHeadQualifier(StringBuilder builder) {
		if (quals.size() != 0) {
			quals.get(0).insert(builder);
		}
	}

	@Override
	protected void parseInternal() throws MDException {
		// TODO: consider a do-while loop so we do not need this initial test for an empty
		//  qualification, but also need to make sure MDQualifier logic also handles the first
		//  '@' in the qualifier, which might not be possible at this time with the immediate
		//  qualifier creation below (probably should wait to do this until when we refactor
		//  MDMang to use factory models).  The other solution is to look for any place that an
		//  MDQualification is used (but not as part of a MDQualfiedName or MDBasicName)
//		if (dmang.peek() == '@' && dmang.peek(1) == '@') {
//			// We have an empty qualification.  Remove the first '@' and the second one will
//			// be handled below.
//			dmang.increment();
//		}
		// We currently have a check to see if the index has moved (loc) to know to abort the
		//  processing of this loop.  We could have also done a loop check on the '`' character
		//  from an LLVM suffix on mangled "type" name that looks like:
		//  "`fedcba98" ('`' character followed by exactly 8 (zero padded) hex digits
		//  TODO:  need to determine what they are and where they should get processed... but
		//    could be part of end of MDQualification, MDQualifiedName, MDClassType,
		//    MDQuestionModifierType, or at same level as complete mangled name.  For now, we
		//    have put the processing in MDQuestionModifierType, but this will take future study
		//    to determine what it is and to what object it belongs.
		//    We have a similar issue with dot-separated symbols... needs more study.
		while ((dmang.peek() != MDMang.DONE) && (dmang.peek() != '@')) {
			int loc = dmang.getIndex();
			MDQualifier qual = new MDQualifier(dmang);
			qual.parse();
			// This is a quick fix to prevent infinite looping when the next character is not
			//  expected.  TODO: need to work on code the breaks symbols on these other
			//  characters that we have seen such as '.' and '`'.
			if (dmang.getIndex() == loc) {
				break;
			}
			quals.add(qual);
		}
		if (dmang.peek() == '@') {
			dmang.increment(); // Skip past @.
		}
//		// For future debugging to try to figure out where to process the '`' suffix
//		if (dmang.peek() == '`') {
//			Exception e = new Exception();
//			StackTraceElement[] trace = e.getStackTrace();
//			StringBuilder builder = new StringBuilder();
//			for (StackTraceElement t : trace) {
//				String s = t.toString();
//				builder.append(s);
//				builder.append('\n');
//				if (s.contains("MDMang.demangle(")) {
//					System.out.println(builder.toString());
//					break;
//				}
//			}
//		}
	}

	/**
	 * Provides iterator of MDQualifiers, where the last iteration is the namespace root
	 * @return the iterator
	 */
	@Override
	public Iterator<MDQualifier> iterator() {
		return quals.iterator();
	}
}

/******************************************************************************/
/******************************************************************************/
