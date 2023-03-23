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
package ghidra.app.util.viewer.field;

import generic.theme.GColor;

public class ListingColors {
	// @formatter:off

	public static final GColor BACKGROUND = new GColor("color.bg.listing");

	public static final GColor ADDRESS = new GColor("color.fg.listing.address");
	public static final GColor BYTES = new GColor("color.fg.listing.bytes");
	public static final GColor EXT_ENTRY_POINT = new GColor("color.fg.listing.ext.entrypoint");
	public static final GColor FIELD_NAME = new GColor("color.fg.listing.fieldname");
	public static final GColor SEPARATOR = new GColor("color.fg.listing.separator");
	public static final GColor UNDERLINE = new GColor("color.fg.listing.underline");
	public static final GColor ARRAY_VALUES = new GColor("color.fg.listing.array.values");
	public static final GColor BYTES_ALIGNMENT = new GColor("color.fg.listing.bytes.alignment");
	public static final GColor BLOCK_START = new GColor("color.fg.listing.block.start");
	
	public static final GColor CONSTANT = new GColor("color.fg.listing.constant");
	public static final GColor REF_BAD = new GColor("color.fg.listing.ref.bad");
	public static final GColor EXT_REF_UNRESOLVED = new GColor("color.fg.listing.ext.ref.unresolved");
	public static final GColor EXT_REF_RESOLVED = new GColor("color.fg.listing.ext.ref.resolved");
	public static final GColor REGISTER = new GColor("color.fg.listing.register");
	public static final GColor PARALLEL_INSTRUCTION = new GColor("color.fg.listing.instruction.parallel");

	
	public static class XrefColors {
		public static final GColor DEFAULT = new GColor("color.fg.listing.xref");
		public static final GColor OFFCUT = new GColor("color.fg.listing.xref.offcut");
		public static final GColor READ = new GColor("color.fg.listing.xref.read");
		public static final GColor WRITE = new GColor("color.fg.listing.xref.write");
		public static final GColor OTHER = new GColor("color.fg.listing.xref.other");
	}
	
	public static class PcodeColors {
		public static final GColor LABEL = new GColor("color.fg.listing.pcode.label");
		public static final GColor ADDRESS_SPACE = new GColor("color.fg.listing.pcode.address.space");
		public static final GColor VARNODE = new GColor("color.fg.listing.pcode.varnode");
		public static final GColor USEROP = new GColor("color.fg.listing.pcode.userop");
	}

	public static class MnemonicColors {
		public static final GColor NORMAL = new GColor("color.fg.listing.mnemonic");
		public static final GColor OVERRIDE = new GColor("color.fg.listing.mnemonic.override");
		public static final GColor UNIMPLEMENTED = new GColor("color.fg.listing.mnemonic.unimplemented");
	}
	
	public static class CommentColors {
		public static final GColor AUTO = new GColor("color.fg.listing.comment.auto");
		public static final GColor EOL = new GColor("color.fg.listing.comment.eol");
		public static final GColor PLATE= new GColor("color.fg.listing.comment.plate");
		public static final GColor POST= new GColor("color.fg.listing.comment.post");
		public static final GColor PRE= new GColor("color.fg.listing.comment.pre");
		public static final GColor REPEATABLE = new GColor("color.fg.listing.comment.repeatable");
		public static final GColor REF_REPEATABLE = new GColor("color.fg.listing.comment.ref.repeatable");
	}
	
	public static class LabelColors {
		public static final GColor LOCAL = new GColor("color.fg.listing.label.local");
		public static final GColor NON_PRIMARY = new GColor("color.fg.listing.label.non.primary");
		public static final GColor PRIMARY = new GColor("color.fg.listing.label.primary");
		public static final GColor UNREFERENCED = new GColor("color.fg.listing.label.unreferenced");
	}
	
	public static class FunctionColors {
		public static final GColor CALL_FIXUP = new GColor("color.fg.listing.function.callfixup");
		public static final GColor NAME = new GColor("color.fg.listing.function.name");
		public static final GColor PARAM = new GColor("color.fg.listing.function.param");
		public static final GColor PARAM_AUTO = new GColor("color.fg.listing.function.param.auto");
		public static final GColor PARAM_CUSTOM = new GColor("color.fg.listing.function.param.custom");
		public static final GColor PARAM_DYNAMIC = new GColor("color.fg.listing.function.param.dynamic");
		public static final GColor RETURN_TYPE = new GColor("color.fg.listing.function.return.type");
		public static final GColor SOURCE = new GColor("color.fg.listing.function.source");
		public static final GColor TAG = new GColor("color.fg.listing.function.tag");
		public static final GColor VARIABLE = new GColor("color.fg.listing.function.variable");
		public static final GColor VARIABLE_ASSIGNED = new GColor("color.fg.listing.function.variable.assigned");
		public static final GColor THUNK = new GColor("color.fg.listing.function.name.thunk");
	}
	
	public static class FlowArrowColors {
		public static final GColor ACTIVE = new GColor("color.fg.listing.flow.arrow.active");
		public static final GColor INACTIVE = new GColor("color.fg.listing.flow.arrow.inactive");
		public static final GColor SELECTED = new GColor("color.fg.listing.flow.arrow.selected");
	}
	
	public static class MaskColors {
		public static final GColor BITS = new GColor("color.fg.listing.mask.bits");
		public static final GColor LABEL = new GColor("color.fg.listing.mask.label");
		public static final GColor VALUE = new GColor("color.fg.listing.mask.value");
		
	}
	// @formatter:on

}
