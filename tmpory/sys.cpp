#include <iostream>
#include <string>
#include <fstream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <unistd.h>  // Include the header for 'access' and 'F_OK'

// Function to execute a shell command and return its output as a string
std::string executeCommand(const std::string& command) {
    std::shared_ptr<FILE> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    char buffer[128];
    std::string result = "";
    while (!feof(pipe.get())) {
        if (fgets(buffer, 128, pipe.get()) != nullptr) {
            result += buffer;
        }
    }
    return result;
}

// Function to display log files
void displayLog(const std::string& logFileName) {
    std::ifstream logFile(logFileName);
    if (logFile.is_open()) {
        std::string line;
        while (std::getline(logFile, line)) {
            std::cout << line << std::endl;
        }
        logFile.close();
    } else {
        std::cerr << "Failed to open " << logFileName << std::endl;
    }
}

// Function to display file contents
void displayFileContents(const std::string& fileName) {
    std::ifstream file(fileName);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            std::cout << line << std::endl;
        }
        file.close();
    } else {
        std::cerr << "Failed to open " << fileName << std::endl;
    }
}

int main() {
    int choice;
    int processChoice;
    std::string processName;
    int logsChoice;
    int modulesChoice;
    int userGroupChoice;
    int runlevelChoice;
    int result; // Declare result here
    std::string pgrepCommand; // Declare pgrepCommand here
    std::string moduleName;
    std::string modinfoCommand;

    while (true) {
        std::cout << "Linux System Information:" << std::endl;
        std::cout << "1. Hostname and System Identification" << std::endl;
        std::cout << "2. Kernel and System Information" << std::endl;
        std::cout << "3. Distribution-Specific Information" << std::endl;
        std::cout << "4. CPU Information" << std::endl;
        std::cout << "5. Memory Information" << std::endl;
        std::cout << "6. Disk and File System Information" << std::endl;
        std::cout << "7. Network Information" << std::endl;
        std::cout << "8. Hardware Information" << std::endl;
        std::cout << "9. Software Information" << std::endl;
        std::cout << "10. Processes Information" << std::endl;
        std::cout << "11. System Logs and Authentication Logs" << std::endl;
        std::cout << "12. Users and Groups Information" << std::endl;
        std::cout << "13. Runlevel and Services Information" << std::endl;
        std::cout << "14. Kernel Modules Information" << std::endl;
        std::cout << "15. Exit" << std::endl;
        std::cout << "Enter your choice: ";
        std::cin >> choice;

        switch (choice) {
            case 1:
                std::cout << "Hostname and System Identification:" << std::endl;
                std::system("hostnamectl");
                break;
            case 2:
                std::cout << "Kernel and System Information:" << std::endl;
                std::system("uname -a");
                break;
            case 3:
                std::cout << "Distribution-Specific Information:" << std::endl;
                std::system("lsb_release -a");
                break;
            case 4:
                std::cout << "CPU Information:" << std::endl;
                std::system("lscpu");
                std::system("cat /proc/cpuinfo");
                break;
            case 5:
                std::cout << "Memory Information:" << std::endl;
                std::system("free -m");
                std::system("cat /proc/meminfo");
                break;
            case 6:
                std::cout << "Disk and File System Information:" << std::endl;
                std::system("df -h");
                std::system("lsblk");
                std::system("fdisk -l");
                std::system("mount");
                break;
            case 7:
                std::cout << "Network Information:" << std::endl;
                std::system("ifconfig");
                std::system("netstat -tuln");
                std::system("route -n");
                break;
            case 8:
                std::cout << "Hardware Information:" << std::endl;
                std::system("lshw");
                std::system("lspci");
                std::system("lsusb");
                break;
            case 9:
                std::cout << "Software Information:" << std::endl;
                std::system("dpkg -l");
                std::system("rpm -qa");
                std::system("dpkg -l | grep ^ii");
                std::system("rpm -qa | sort");
                std::system("cat /etc/apt/sources.list");
                std::system("cat /etc/yum.repos.d/*.repo");
                break;
            case 10:
                while (true) {
                    std::cout << "Processes Information:" << std::endl;
                    std::cout << "1. Display real-time system statistics (top or htop)" << std::endl;
                    std::cout << "2. List all processes and their details (ps aux)" << std::endl;
                    std::cout << "3. Get the process ID (PID) of a specific process (pgrep)" << std::endl;
                    std::cout << "4. Back to Main Menu" << std::endl;
                    std::cout << "Enter your choice: ";
                    std::cin >> processChoice;
                    switch (processChoice) {
                        case 1:
                            std::system("top");
                            break;
                        case 2:
                            std::system("ps aux");
                            break;
                        case 3:
                            std::cout << "Enter the process name: ";
                            std::cin >> processName;
                            pgrepCommand = "pgrep " + processName;
                            result = std::system(pgrepCommand.c_str());
                            if (WIFEXITED(result) && WEXITSTATUS(result) == 0) {
                                std::cout << "Process ID (PID): " << WEXITSTATUS(result) << std::endl;
                            } else {
                                std::cerr << "Process not found or an error occurred." << std::endl;
                            }
                            break;
                        case 4:
                            break;
                        default:
                            std::cout << "Invalid choice. Please try again." << std::endl;
                    }
                    if (processChoice == 4) {
                        break;
                    }
                }
                break;
            case 11:
                while (true) {
                    std::cout << "System Logs and Authentication Logs:" << std::endl;
                    std::cout << "1. Display system logs" << std::endl;
                    std::cout << "2. Display authentication logs" << std::endl;
                    std::cout << "3. Back to Main Menu" << std::endl;
                    std::cout << "Enter your choice: ";
                    std::cin >> logsChoice;
                    switch (logsChoice) {
                        case 1:
                            std::system("cat /var/log/syslog");
                            break;
                        case 2:
                            if (access("/var/log/auth.log", F_OK) != -1) {
                                std::system("cat /var/log/auth.log");
                            } else if (access("/var/log/secure", F_OK) != -1) {
                                std::system("cat /var/log/secure");
                            } else {
                                std::cerr << "Authentication log file not found." << std::endl;
                            }
                            break;
                        case 3:
                            break;
                        default:
                            std::cout << "Invalid choice. Please try again." << std::endl;
                    }
                    if (logsChoice == 3) {
                        break;
                    }
                }
                break;
 	    case 12:
                while (true) {
                    std::cout << "Users and Groups Information:" << std::endl;
                    std::cout << "1. List User Accounts" << std::endl;
                    std::cout << "2. List Group Accounts" << std::endl;
                    std::cout << "3. Back to Main Menu" << std::endl;
                    std::cout << "Enter your choice: ";
                    std::cin >> userGroupChoice;
                    switch (userGroupChoice) {
                        case 1:
                            std::system("cat /etc/passwd");
                            break;
                        case 2:
                            std::system("cat /etc/group");
                            break;
                        case 3:
                            break;
                        default:
                            std::cout << "Invalid choice. Please try again." << std::endl;
                    }
                    if (userGroupChoice == 3) {
                        break;
                    }
                }
                break;
            case 13:
                while (true) {
                    std::cout << "Runlevel and Services Information:" << std::endl;
                    std::cout << "1. Show Current Runlevel" << std::endl;
                    std::cout << "2. List Available Services" << std::endl;
                    std::cout << "3. Back to Main Menu" << std::endl;
                    std::cout << "Enter your choice: ";
                    std::cin >> runlevelChoice;
                    switch (runlevelChoice) {
                        case 1:
                            std::system("runlevel");
                            break;
                        case 2:
                            std::system("service --status-all 2>&1 || systemctl list-units --type=service");
                            break;
                        case 3:
                            break;
                        default:
                            std::cout << "Invalid choice. Please try again." << std::endl;
                    }
                    if (runlevelChoice == 3) {
                        break;
                    }
                }
                break;
            case 14:
                while (true) {
                    std::cout << "Kernel Modules Information:" << std::endl;
                    std::cout << "1. List Loaded Kernel Modules (lsmod)" << std::endl;
                    std::cout << "2. Display Information About a Specific Kernel Module (modinfo)" << std::endl;
                    std::cout << "3. Back to Main Menu" << std::endl;
                    std::cout << "Enter your choice: ";
                    std::cin >> modulesChoice;
                    switch (modulesChoice) {
                        case 1:
                            std::system("lsmod");
                            break;
                        case 2:
                            std::cout << "Enter the name of the kernel module: ";
                            std::cin >> moduleName;
                            modinfoCommand = "modinfo " + moduleName;
                            std::system(modinfoCommand.c_str());
                            break;
                        case 3:
                            break;
                        default:
                            std::cout << "Invalid choice. Please try again." << std::endl;
                    }
                    if (modulesChoice == 3) {
                        break;
                    }
                }
                break;
            case 15:
                return 0;
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
        }
    }

    return 0;
}

