#include "proc-map.H"
#include "pin.H"
#include "utils.H"
#include <iostream>

using namespace std;

int pid = PIN_GetPid();

FILE *readProcMap(const std::string command, short pos) {
    FILE *fp;
    std::stringstream command_string;
    command_string << "cat /proc/" << pid << "/maps";
    if (!command.empty()) {
        command_string << " | grep '" << command
                       << "' | awk '{print $1}' | cut -f" << pos << " -d-";
    }
    const std::string to_pass(command_string.str());
    PT_DEBUG(1, "readProcMap command: " << to_pass.c_str());

    const char *arg = to_pass.c_str();
    fp = popen(arg, "r");
    if (!fp) {
        PT_ERROR("readProcMap failed: " << to_pass.c_str());
    }
    return fp;
}

void printProcMap(void) {
    char buffer[64];
    FILE *fp = readProcMap("", 0);
    if (fp != NULL) {
        while (fgets(buffer, 64, fp) != NULL) {
            std::cout << buffer;
        }
        pclose(fp);
    }
}

ADDRINT getAddrFromProcMap(const std::string command, short pos) {
    char buffer[64];
    FILE *fp = readProcMap(command, pos);
    if (fp != NULL) {
        while (fgets(buffer, 64, fp) != NULL) {
            pclose(fp);
        }
    }

    std::string tmp = "0x" + (std::string)buffer;
    ADDRINT addr = strtol(tmp.c_str(), NULL, 0);

    PT_DEBUG(3, "getAddrFromProcMap returns " << hex << addr);

    return addr;
}
