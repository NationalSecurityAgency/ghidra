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
package ghidra.app.util.recognizer;

public class SbxRecognizer implements Recognizer {
    @Override
	public String recognize(byte[] bytes) {
        if (bytes.length >= numberOfBytesRequired()) {
            if (bytes[0] == (byte) 0x53 &&
                bytes[1] == (byte) 0x42 &&
                bytes[2] == (byte) 0x31 &&
                bytes[3] == (byte) 0x00) {
                return "File appears to be an SBX compressed file";
            }
        }
        return null;
    }

    @Override
	public int getPriority() {
        return 100;
    }

    @Override
	public int numberOfBytesRequired() {
        return 4;
    }
}
