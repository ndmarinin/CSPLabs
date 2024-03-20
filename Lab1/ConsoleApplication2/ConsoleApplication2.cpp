#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include "Tasks.h"

int main() {
    Task1();

    int type = getUserInput("Enter type: "); // Input from command line

    std::cout << "\n-----Task 2-----" << std::endl;
    LPTSTR psName = Task2(type);

    std::cout << "\n-----Task 3-----" << std::endl;
    HCRYPTPROV hCryptProv = Task3(psName, type);

    LPCWSTR nameContainer = L"Nikita Container";

    std::cout << "\n-----Task 4-----" << std::endl;
    Task4(hCryptProv, psName, type, nameContainer); // Create a container with the name {nameContainer}

    std::cout << "\n-----Task 4 - Additional Information-----" << std::endl;
    printNamesContFromProv(hCryptProv); // Output all containers of our selected provider {hCryptProv}

    std::cout << "\n-----Task 5-----" << std::endl;
    Task5(hCryptProv, psName, type, nameContainer); // Delete the container with the name {nameContainer} from the provider {hCryptProv}

    std::cout << "\n-----Cleanup-----" << std::endl;
    LocalFree(psName);

    if (CryptReleaseContext(hCryptProv, 0)) {
        std::cout << "Context successfully deleted\n";
    }
    else {
        std::cout << "Context was not deleted\n";
    }

    return 0;
}
