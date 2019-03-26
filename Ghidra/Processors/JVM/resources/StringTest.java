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
class StringTest{


    public static void main(String[] args){
        System.out.println("\u0024\u00a5\u00a2\u20ac");
        System.out.println("\u00a5\u00a2\u20ac");
        return;
    }

    public String test1(){
        return "input1";
    }
    
    public int test2(){
        return "input1".length();
    }
}
