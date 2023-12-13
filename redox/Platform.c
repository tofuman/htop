/*
htop - redox/Platform.c
(C) 2014 Hisham H. Muhammad
(C) 2015 David C. Hunt
Released under the GNU GPLv2+, see the COPYING file
in the source distribution for its full text.
*/

#include "config.h" // IWYU pragma: keep

#include "redox/Platform.h"

#include <math.h>
#include <sys/statvfs.h>

#include "CPUMeter.h"
#include "ClockMeter.h"
#include "DateMeter.h"
#include "DateTimeMeter.h"
#include "HostnameMeter.h"
#include "LoadAverageMeter.h"
#include "Macros.h"
#include "MemoryMeter.h"
#include "MemorySwapMeter.h"
#include "SwapMeter.h"
#include "SysArchMeter.h"
#include "TasksMeter.h"
#include "UptimeMeter.h"


const ScreenDefaults Platform_defaultScreens[] = {
   {
      .name = "Main",
      .columns = "PID USER PRIORITY NICE M_VIRT M_RESIDENT STATE PERCENT_CPU PERCENT_MEM TIME Command",
      .sortKey = "PERCENT_CPU",
   },
};

const unsigned int Platform_numberOfDefaultScreens = ARRAYSIZE(Platform_defaultScreens);

const SignalItem Platform_signals[] = {
   { .name = " 0 Cancel",    .number =  0 },
};

const unsigned int Platform_numberOfSignals = ARRAYSIZE(Platform_signals);

const MeterClass* const Platform_meterTypes[] = {
   &CPUMeter_class,
   &ClockMeter_class,
   &DateMeter_class,
   &DateTimeMeter_class,
   &LoadAverageMeter_class,
   &LoadMeter_class,
   &MemoryMeter_class,
   &TasksMeter_class,
   &BatteryMeter_class,
   &HostnameMeter_class,
   &SysArchMeter_class,
   &UptimeMeter_class,
   &AllCPUsMeter_class,
   &AllCPUs2Meter_class,
   &AllCPUs4Meter_class,
   &AllCPUs8Meter_class,
   &LeftCPUsMeter_class,
   &RightCPUsMeter_class,
   &LeftCPUs2Meter_class,
   &RightCPUs2Meter_class,
   &LeftCPUs4Meter_class,
   &RightCPUs4Meter_class,
   &LeftCPUs8Meter_class,
   &RightCPUs8Meter_class,
   &BlankMeter_class,
   NULL
};

static const char Platform_redox[] = "redox";

bool Platform_init(void) {
   /* no platform-specific setup needed */
   return true;
}

void Platform_done(void) {
   /* no platform-specific cleanup needed */
}

void Platform_setBindings(Htop_Action* keys) {
   /* no platform-specific key bindings */
   (void) keys;
}

int Platform_getUptime() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

void Platform_getLoadAverage(double* one, double* five, double* fifteen) {
   *one = 0;
   *five = 0;
   *fifteen = 0;
}

int Platform_getMaxPid() {
   return 1;
}

double Platform_setCPUValues(Meter* this, unsigned int cpu) {
   (void) cpu;

   double* v = this->values;
   v[CPU_METER_FREQUENCY] = NAN;
   v[CPU_METER_TEMPERATURE] = NAN;

   this->curItems = 1;

   return 0.0;
}

void Platform_setMemoryValues(Meter* this) {
    struct statvfs stat;
    int fd = open("memory:", O_RDONLY);
    fstatvfs(fd, &stat);
    close(fd);

    this->total = stat.f_blocks * stat.f_bsize / 1024; // total
    this->values[0] = (stat.f_blocks - stat.f_bfree) * stat.f_bsize / 1024; // used
    this->values[4] = stat.f_bavail * stat.f_bsize / 1024; // free
}

void Platform_setSwapValues(Meter* this) {
    this->total = 0;
    this->values[0] = 0;
    this->values[0] = 0;
}

char* Platform_getProcessEnv(pid_t pid) {
   (void) pid;
   return NULL;
}

char* Platform_getInodeFilename(pid_t pid, ino_t inode) {
   (void)pid;
   (void)inode;
   return NULL;
}

FileLocks_ProcessData* Platform_getProcessLocks(pid_t pid) {
   (void)pid;
   return NULL;
}

bool Platform_getDiskIO(DiskIOData* data) {
   (void)data;
   return false;
}

bool Platform_getNetworkIO(NetworkIOData* data) {
   (void)data;
   return false;
}

void Platform_getBattery(double* percent, ACPresence* isOnAC) {
   *percent = NAN;
   *isOnAC = AC_ERROR;
}

void Platform_getHostname(char* buffer, size_t size) {
   String_safeStrncpy(buffer, Platform_redox, size);
}

void Platform_getRelease(char** string) {
   *string = xStrdup(Platform_redox);
}