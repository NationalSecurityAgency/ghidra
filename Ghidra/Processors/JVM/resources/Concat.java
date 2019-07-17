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
class Concat{

    public String concat(String str1, String str2){
        printIt("!" + str1 + "@" + str2);
        return "done";
    }


    public String concat1(String str1, String str2){
        int x  = 0;
        StringBuilder sb = new StringBuilder("test");
        sb.append("asdf");
        sb.append("asdfsfasdf");
        sb.append("123123");
        printIt(sb.toString());
        return "done" + Integer.toString(x);
    }


    public void printIt(String str){
        System.out.println(str);
        return;
    }

}
