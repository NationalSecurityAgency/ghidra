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
// WinHelloCPP.cpp : Defines the entry point for the application.
//

#include "Wallace.h"
#include "Gadget.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Person *personList = NULL;

void addPeople(Person **list) {
	addPerson(list, "Lord Victor Quartermaine");
	addPerson(list, "Lady Tottington");
	addPerson(list, "Were Rabbit");
	addPerson(list, "Rabbit");
	addPerson(list, "Gromit");
	addPerson(list, "Wallace");
}

void initializePeople(Person *people) {
	int index = 0;

	do {
		people->likesCheese = (rand() * 2) < 1;
		people->id = index++;
		people = people->next;
	} while (people != NULL);
}

void addPerson (Person **list, char *name) {
	Person *person = new(Person);
	strncpy_s(person->name, name, sizeof(person->name));

	person->next = *list;
	*list = person;
}

Gadget* deployGadget() {
	Gadget *gadget = new Gadget("Infrared Garden Gnome");

	Person *pp = personList;
	while (pp != NULL) {
		if (strcmp(pp->name, "Wallace")==0) { 
			gadget->use(pp);
		}
		pp = pp->next;
	}

	return gadget;
}

int main(int argc, char **argv) {
	addPeople(&personList);
 	initializePeople(personList);
	Gadget *gadget = deployGadget();
	gadget->print();
}
