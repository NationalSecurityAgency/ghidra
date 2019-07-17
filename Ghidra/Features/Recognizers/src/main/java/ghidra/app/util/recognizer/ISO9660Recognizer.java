/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.recognizer;

public class ISO9660Recognizer implements Recognizer {
    public String recognize(byte[] bytes) {
        if (bytes.length >= 32774) {
            if (bytes[32769] == (byte) 0x43 &&
                bytes[32770] == (byte) 0x44 &&
                bytes[32771] == (byte) 0x30 &&
                bytes[32772] == (byte) 0x30 &&
                bytes[32773] == (byte) 0x31) {
                return "File appears to be an ISO9660 (CD) image";
            }
        }
        if (bytes.length >= 34822) {
            if (bytes[34817] == (byte) 0x43 &&
                bytes[34818] == (byte) 0x44 &&
                bytes[34819] == (byte) 0x30 &&
                bytes[34820] == (byte) 0x30 &&
                bytes[34821] == (byte) 0x31) {
                return "File appears to be an ISO9660 (CD) image";
            }
        }
        if (bytes.length >= 36870) {
            if (bytes[36865] == (byte) 0x43 &&
                bytes[36866] == (byte) 0x44 &&
                bytes[36867] == (byte) 0x30 &&
                bytes[36868] == (byte) 0x30 &&
                bytes[36869] == (byte) 0x31) {
                return "File appears to be an ISO9660 (CD) image";
            }
        }
        return null;
    }

    public int getPriority() {
        return 100;
    }

    public int numberOfBytesRequired() {
        return 36870;
    }
}
