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
// WinHelloCPP.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "WinHelloCPP.h"
#include "Gadget.h"
#include <stdio.h>

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;								// current instance
TCHAR szTitle[MAX_LOADSTRING];					// The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];			// the main window class name

// Forward declarations of functions included in this code module:
ATOM				MyRegisterClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK	About(HWND, UINT, WPARAM, LPARAM);

Person *personList = NULL;

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{


	addPeople(&personList);
 	initializePeople(personList);

	MSG msg;
	HACCEL hAccelTable;

	// Initialize global strings
	LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInstance, IDC_WINHELLOCPP, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);

	// Perform application initialization:
	if (!InitInstance (hInstance, nCmdShow)) 
	{
		return FALSE;
	}

	hAccelTable = LoadAccelerators(hInstance, (LPCTSTR)IDC_WINHELLOCPP);

	// Main message loop:
	while (GetMessage(&msg, NULL, 0, 0)) 
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) 
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int) msg.wParam;
}


void initializeStructure (WNDCLASSEX *wcex, HINSTANCE hInstance) {
	
	wcex->cbSize = sizeof(WNDCLASSEX); 

	wcex->style			= CS_HREDRAW | CS_VREDRAW;
	wcex->lpfnWndProc	= (WNDPROC)WndProc;
	wcex->cbClsExtra	= 0;
	wcex->cbWndExtra	= 0;
	wcex->hInstance		= hInstance;
	wcex->hIcon			= LoadIcon(hInstance, (LPCTSTR)IDI_WINHELLOCPP);
	wcex->hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex->hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex->lpszMenuName	= (LPCTSTR)IDC_WINHELLOCPP;
	wcex->lpszClassName	= szWindowClass;
	wcex->hIconSm		= LoadIcon(wcex->hInstance, (LPCTSTR)IDI_SMALL);
}

//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
//  COMMENTS:
//
//    This function and its usage are only necessary if you want this code
//    to be compatible with Win32 systems prior to the 'RegisterClassEx'
//    function that was added to Windows 95. It is important to call this function
//    so that the application will get 'well formed' small icons associated
//    with it.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	initializeStructure(&wcex, hInstance);

	return RegisterClassEx(&wcex);
}



//
//   FUNCTION: InitInstance(HANDLE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   HWND hWnd;

   hInst = hInstance; // Store instance handle in our global variable

   hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, unsigned, WORD, LONG)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND	- process the application menu
//  WM_PAINT	- Paint the main window
//  WM_DESTROY	- post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	PAINTSTRUCT ps;
	HDC hdc;

	switch (message) 
	{
	case WM_COMMAND:
		wmId    = LOWORD(wParam); 
		wmEvent = HIWORD(wParam); 
		// Parse the menu selections:
		switch (wmId)
		{
		case IDM_ABOUT:
			DialogBox(hInst, (LPCTSTR)IDD_ABOUTBOX, hWnd, (DLGPROC)About);
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
		}
		break;
	case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		
		doPaint(hdc, ps.rcPaint);

		EndPaint(hWnd, &ps);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

// Message handler for about box.
LRESULT CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
		return TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) 
		{
			EndDialog(hDlg, LOWORD(wParam));
			return TRUE;
		}
		break;
	}
	return FALSE;
}

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

		printf("%s %s\n", people->name, (people->likesCheese ? " likes Cheese" :
			" hates Cheese"));

		people = people->next;
	} while (people != NULL);
}

void addPerson (Person **list, char *name) {
	Person *person = new(Person);
	strncpy_s (person->name, name, sizeof(person->name));

	person->next = *list;
	*list = person;
}

void doPaint(HDC hDC, RECT rect) {
	MoveToEx(hDC, rect.top, rect.left, NULL);
	LineTo(hDC, rect.bottom, rect.right);

	int maxx = abs(rect.right - rect.left) + 1;
	int maxy = abs(rect.top - rect.bottom) + 1;
	Person *next = personList;
	while (next != NULL) {
		TextOut(hDC, rand()%maxx, rand()%maxy, next->name, strlen(next->name));
		next = next->next;
	}

	Gadget *gadget = new Gadget("Infrared Garden Gnome");
	gadget->use(personList);
}
