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
package ghidra.file.formats.yaffs2;

public class YAFFS2Constants {

	public final static int MAGIC_SIZE = 11;

	public final static int FILE_NAME_SIZE = 256;

	public final static int ALIAS_FILE_NAME_SIZE = 160;

	public final static int RECORD_SIZE = 2112;

	public final static int HEADER_SIZE = 512;

	public final static int EXTENDED_TAGS_SIZE = 64;

	public final static int DATA_BUFFER_SIZE = 2048;

	public final static int EMPTY_DATA_SIZE = 1536;

}
