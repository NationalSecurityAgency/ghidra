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
package ghidra.app.util.demangler.gnu;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

import org.junit.Test;

import static ghidra.app.util.demangler.gnu.GnuDemanglerFormat.*;

import java.io.IOException;

public class GnuDemanglerOptionsTest extends AbstractGhidraHeadlessIntegrationTest {

    @Test
    public void testAuto_withDeprecated() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(AUTO, true);
        getNativeProcess(options);
    }
    
    @Test
    public void testAuto_withModern() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(AUTO, false);
        getNativeProcess(options);
    }

    @Test
    public void testGnu_withDeprecated() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(GNU, true);
        getNativeProcess(options);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testGnu_withModern() {
        new GnuDemanglerOptions(GNU, false);
    }

    @Test
    public void testLucid_withDeprecated() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(LUCID, true);
        getNativeProcess(options);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testLucid_withModern() {
        new GnuDemanglerOptions(LUCID, false);
    }

    @Test
    public void testArm_withDeprecated() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(ARM, true);
        getNativeProcess(options);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testArm_withModern() {
        new GnuDemanglerOptions(ARM, false);
    }

    @Test
    public void testHp_withDeprecated() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(HP, true);
        getNativeProcess(options);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testHp_withModern() {
        new GnuDemanglerOptions(HP, false);
    }

    @Test
    public void testEdg_withDeprecated() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(EDG, true);
        getNativeProcess(options);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testEdg_withModern() {
        new GnuDemanglerOptions(EDG, false);
    }

    @Test
    public void testGnuV3_withDeprecated() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(GNUV3, true);
        getNativeProcess(options);
    }
    
    @Test
    public void testGnuV3_withModern() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(GNUV3, false);
        getNativeProcess(options);
    }

    @Test
    public void testJava_withDeprecated() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(JAVA, true);
        getNativeProcess(options);
    }
    
    @Test
    public void testJava_withModern() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(JAVA, false);
        getNativeProcess(options);
    }

    @Test
    public void testGnat_withDeprecated() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(GNAT, true);
        getNativeProcess(options);
    }
    
    @Test
    public void testGnat_withModern() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(GNAT, false);
        getNativeProcess(options);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDlang_withDeprecated() {
        new GnuDemanglerOptions(DLANG, true);
    }
    
    @Test
    public void testDlang_withModern() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(DLANG, false);
        getNativeProcess(options);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRust_withDeprecated() {
        new GnuDemanglerOptions(RUST, true);
    }
    
    @Test
    public void testRust_withModern() throws IOException {
        GnuDemanglerOptions options = new GnuDemanglerOptions(RUST, false);
        getNativeProcess(options);
    }

    private static GnuDemanglerNativeProcess getNativeProcess(GnuDemanglerOptions options)
            throws IOException {
        String demanglerName = options.getDemanglerName();
		String applicationOptions = options.getDemanglerApplicationArguments();
		return GnuDemanglerNativeProcess.getDemanglerNativeProcess(demanglerName,
			applicationOptions);
    }
}
