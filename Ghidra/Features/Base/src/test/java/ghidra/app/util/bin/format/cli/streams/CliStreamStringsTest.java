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
package ghidra.app.util.bin.format.cli.streams;

import static org.junit.Assert.*;

import java.io.*;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.format.pe.cli.CliStreamHeader;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamStrings;
import ghidra.util.LittleEndianDataConverter;

public class CliStreamStringsTest extends AbstractGTest {

	private CliStreamStrings initCliStreamStrings() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(new byte[] { 0, 0, 0, 0 }); // offset
		baos.write(new byte[] { 0, 0, 0, 0 }); // size
		baos.write(new byte[] { (byte) 'a', (byte) 'b', (byte) 'c', 0 }); // name
		int offset = baos.size();
		PrintWriter pw = new PrintWriter(baos, false, StandardCharsets.UTF_8);
		pw.write("\0");
		pw.write("test1\0");
		pw.write("test2\0");
		pw.write("ab\ucc01\u1202ab\0");
		pw.write("last\0");
		pw.flush();
		int size = baos.size() - offset;
		byte[] bytes = baos.toByteArray();

		LittleEndianDataConverter.INSTANCE.putInt(bytes, 0, offset);
		LittleEndianDataConverter.INSTANCE.putInt(bytes, 4, size);

		ByteArrayProvider bap = new ByteArrayProvider(bytes);
		BinaryReader br = new BinaryReader(bap, true);

		CliStreamHeader csh = new CliStreamHeader(null, br);
		CliStreamStrings css = new CliStreamStrings(csh, offset, 0, br);

		return css;
	}

	private CliStreamStrings initCliStreamStringsEmpty() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(new byte[] { 0, 0, 0, 0 }); // offset
		baos.write(new byte[] { 0, 0, 0, 0 }); // size
		baos.write(new byte[] { (byte) 'a', (byte) 'b', (byte) 'c', 0 }); // name
		int offset = baos.size();
		PrintWriter pw = new PrintWriter(baos, false, StandardCharsets.UTF_8);
		pw.write("\0");
		pw.flush();
		int size = baos.size() - offset;
		byte[] bytes = baos.toByteArray();

		LittleEndianDataConverter.INSTANCE.putInt(bytes, 0, offset);
		LittleEndianDataConverter.INSTANCE.putInt(bytes, 4, size);

		ByteArrayProvider bap = new ByteArrayProvider(bytes);
		BinaryReader br = new BinaryReader(bap, true);

		CliStreamHeader csh = new CliStreamHeader(null, br);
		CliStreamStrings css = new CliStreamStrings(csh, offset, 0, br);

		return css;
	}

	private CliStreamStrings initCliStreamStringsHeaderOnly() throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(new byte[] { 0, 0, 0, 0 }); // offset
		baos.write(new byte[] { 0, 0, 0, 0 }); // size
		baos.write(new byte[] { (byte) 'a', (byte) 'b', (byte) 'c', 0 }); // name
		int offset = baos.size();
		PrintWriter pw = new PrintWriter(baos, false, StandardCharsets.UTF_8);
		pw.flush();
		int size = baos.size() - offset;
		byte[] bytes = baos.toByteArray();

		LittleEndianDataConverter.INSTANCE.putInt(bytes, 0, offset);
		LittleEndianDataConverter.INSTANCE.putInt(bytes, 4, size);

		ByteArrayProvider bap = new ByteArrayProvider(bytes);
		BinaryReader br = new BinaryReader(bap, true);

		CliStreamHeader csh = new CliStreamHeader(null, br);
		CliStreamStrings css = new CliStreamStrings(csh, offset, 0, br);

		return css;
	}

	@Test
	public void testParse() throws IOException {
		CliStreamStrings css = initCliStreamStrings();
		assertEquals(css.parse(), true);
	}

	@Test
	public void testGetString() throws IOException {
		// Test a normally formed blob of UTF-8 strings
		CliStreamStrings css = initCliStreamStrings();
		css.parse();

		assertEquals(css.getString(-1), null);
		assertEquals(css.getString(0), "");
		assertEquals(css.getString(1), "test1");
		assertEquals(css.getString(2), "est1");
		assertEquals(css.getString(3), "st1");
		assertEquals(css.getString(4), "t1");
		assertEquals(css.getString(5), "1");
		assertEquals(css.getString(6), "");
		assertEquals(css.getString(7), "test2");
		assertEquals(css.getString(8), "est2");
		assertEquals(css.getString(9), "st2");
		assertEquals(css.getString(10), "t2");
		assertEquals(css.getString(11), "2");
		assertEquals(css.getString(12), "");
		assertEquals(css.getString(13), "ab\ucc01\u1202ab");
		assertEquals(css.getString(14), "b\ucc01\u1202ab");
		assertEquals(css.getString(15), "\ucc01\u1202ab");

		// Invalid conversions -> Unicode Replacement characters
		assertEquals(css.getString(16), "\ufffd\ufffd\u1202ab");
		assertEquals(css.getString(17), "\ufffd\u1202ab");

		assertEquals(css.getString(18), "\u1202ab");

		// Invalid conversions -> Unicode Replacement characters
		assertEquals(css.getString(19), "\ufffd\ufffdab");
		assertEquals(css.getString(20), "\ufffdab");

		assertEquals(css.getString(21), "ab");
		assertEquals(css.getString(22), "b");
		assertEquals(css.getString(23), "");
		assertEquals(css.getString(24), "last");
		assertEquals(css.getString(25), "ast");
		assertEquals(css.getString(26), "st");
		assertEquals(css.getString(27), "t");
		assertEquals(css.getString(28), "");
		assertEquals(css.getString(29), null);
	}

	@Test
	public void testGetStringEmpty() throws IOException {
		// Test a blob that only includes the mandatory single
		// NULL string
		CliStreamStrings css = initCliStreamStringsEmpty();
		css.parse();

		assertEquals(css.getString(0), "");
		assertEquals(css.getString(1), null);
		assertEquals(css.getString(2), null);
	}

	@Test
	public void testGetStringHeaderOnly() throws IOException {
		// Test a blob that for some reason includes the header
		// only and not the mandatory NULL string
		CliStreamStrings css = initCliStreamStringsHeaderOnly();
		css.parse();

		assertEquals(css.getString(0), null);
		assertEquals(css.getString(1), null);
		assertEquals(css.getString(2), null);
	}
}
