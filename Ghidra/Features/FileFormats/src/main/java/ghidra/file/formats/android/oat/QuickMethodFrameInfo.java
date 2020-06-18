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

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * https://android.googlesource.com/platform/art/+/refs/heads/lollipop-release/runtime/quick/quick_method_frame_info.h#53
 * https://android.googlesource.com/platform/art/+/refs/heads/lollipop-mr1-fi-release/runtime/quick/quick_method_frame_info.h#54
 * https://android.googlesource.com/platform/art/+/refs/heads/lollipop-wear-release/runtime/quick/quick_method_frame_info.h#54
 * https://android.googlesource.com/platform/art/+/marshmallow-release/runtime/quick/quick_method_frame_info.h#54
 * https://android.googlesource.com/platform/art/+/refs/heads/nougat-release/runtime/quick/quick_method_frame_info.h#57
 * https://android.googlesource.com/platform/art/+/nougat-mr1-release/runtime/quick/quick_method_frame_info.h#57
 * https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/quick/quick_method_frame_info.h#57
 * https://android.googlesource.com/platform/art/+/refs/heads/oreo-dr3-release/runtime/quick/quick_method_frame_info.h#57
 * https://android.googlesource.com/platform/art/+/refs/heads/oreo-m2-release/runtime/quick/quick_method_frame_info.h#57
 * https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/quick/quick_method_frame_info.h#57
 * https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/quick/quick_method_frame_info.h#57
 * https://android.googlesource.com/platform/art/+/refs/heads/android11-release/runtime/quick/quick_method_frame_info.h#57
 */
public class QuickMethodFrameInfo implements StructConverter {

	final static int SIZE = 12;

	private int frame_size_in_bytes_;
	private int core_spill_mask_;
	private int fp_spill_mask_;

	QuickMethodFrameInfo(BinaryReader reader) throws IOException {
		frame_size_in_bytes_ = reader.readNextInt();
		core_spill_mask_ = reader.readNextInt();
		fp_spill_mask_ = reader.readNextInt();
	}

	public int getFrameSizeInBytes() {
		return frame_size_in_bytes_;
	}

	public int getCoreSpillMask() {
		return core_spill_mask_;
	}

	public int getFpSpillMask() {
		return fp_spill_mask_;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType(QuickMethodFrameInfo.class);
		dataType.setCategoryPath(new CategoryPath("/oat"));
		return dataType;
	}
}
