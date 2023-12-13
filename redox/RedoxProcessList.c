/*
htop - RedoxProcessList.c
(C) 2014 Hisham H. Muhammad
Released under the GNU GPLv2+, see the COPYING file
in the source distribution for its full text.
*/

#include "RedoxProcessList.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/statvfs.h>

#include "ProcessList.h"
#include "RedoxProcess.h"


ProcessList* ProcessList_new(UsersTable* usersTable, Hashtable* dynamicMeters, Hashtable* dynamicColumns, Hashtable* pidMatchList, uid_t userId) {
   ProcessList* this = xCalloc(1, sizeof(ProcessList));
   ProcessList_init(this, Class(Process), usersTable, dynamicMeters, dynamicColumns, pidMatchList, userId);

   this->existingCPUs = 4;
   this->activeCPUs = 4;

   return this;
}

void ProcessList_delete(ProcessList* this) {
   ProcessList_done(this);
   free(this);
}

void ProcessList_goThroughEntries(ProcessList* super, bool pauseProcessUpdate) {

   struct statvfs statfs;
    int fd = open("memory:", O_RDONLY);
    fstatvfs(fd, &statfs);
    close(fd);

    super->totalMem = statfs.f_blocks * statfs.f_bsize; // total
    super->usedMem = (statfs.f_blocks - statfs.f_bfree) * statfs.f_bsize; // used
    super->availableMem = statfs.f_bavail * statfs.f_bsize; // free


   // in pause mode only gather global data for meters (CPU/memory/...)
   if (pauseProcessUpdate) {
      return;
   }
   FILE * fp;
   char line[250];
   size_t len = 250;
   ssize_t read;
   fp = fopen("sys:/context", "r");
   if (fp == NULL){
      return;
   }

   read = fgets(line, len, fp); //skip heading
   if (read == NULL) {
      fclose(fp);
      return;
   }
   while (fgets(line, len, fp) != NULL) {

      bool preExisting;
      Process* proc;
      long pid, pgid, ppid, ruid, rgid, rns, euid, egid, ens, cpu, mem;
      char stat[5];
      char ticks[20];
      char mem_units[5];
      char name[100];

     sscanf(line, "%ld %ld %ld %ld %ld %ld %ld %ld %ld %s %*[#]%ld %*s %s %ld %s %s", &pid, &pgid, &ppid, &ruid, &rgid, &rns, &euid, &egid, &ens, stat, &cpu, ticks, &mem, mem_units, name);

      proc = ProcessList_getProcess(super, pid, &preExisting, RedoxProcess_new);

      /* Empty values */
      proc->time = proc->time + 10;
      proc->pid  = pid;
      proc->ppid = ppid;
      proc->tgid = pid;

      Process_updateComm(proc, "commof16char");
      if (strstr(stat, "RR") == NULL) {
        Process_updateCmdline(proc, name, 0, strlen(name));
        Process_updateExe(proc, name);
      } else if (!preExisting) {
        Process_updateCmdline(proc, "kernel", 0, strlen("kernel"));
      }

      if (proc->settings->ss->flags & PROCESS_FLAG_CWD) {
         free_and_xStrdup(&proc->procCwd, "/current/working/directory");
      }

      proc->updated = true;

      if (stat[1] == 'R') {
        proc->state = RUNNABLE;
        if(strlen(stat) == 3 && stat[2] == '+')
           proc->state = RUNNING;
      } else if (stat[1] == 'B') {
        proc->state = BLOCKED;
      } else if (stat[1] == 'T') {
        proc->state = TRACED;
      } else if (stat[1] == 'S') {
        proc->state = SLEEPING;
      } else if (stat[1] == 'E') {
        proc->state = ZOMBIE;
      } else {
        proc->state = UNKNOWN;
      }


      if (stat[0] == 'K' || stat[0] == 'R') {
        proc->isKernelThread = true;
        proc->isUserlandThread = false;
      } else if (stat[0] == 'U') {
        proc->isUserlandThread = true;
        proc->isKernelThread = false;
      }
      proc->show = true; /* Reflected in proc->settings-> "hideXXX" really */
      proc->pgrp = 0;
      proc->session = 0;
      proc->tty_nr = 0;
      proc->tty_name = NULL;
      proc->tpgid = pgid;
      proc->processor = cpu;

      double mem_scaling = 1;
      if (strcmp(mem_units, "KB")) {
        mem_scaling = 1024;
      } else if (strcmp(mem_units, "MB")) {
        mem_scaling = 1024*1024;
      } else if (strcmp(mem_units, "GB")) {
        mem_scaling = 1024*1024*1024;
      }
      mem = mem * mem_scaling;

      proc->percent_mem = mem / (double)(super->totalMem)* 100.0;
      proc->percent_cpu = 2.5;
      Process_updateCPUFieldWidths(proc->percent_cpu);


      FILE * uid_fp;
      char * uid_path;
      char uid;
      if (0 > asprintf(&uid_path, "proc:%d/uid", pid)){
         return;
      }
      uid_fp = fopen(uid_path, "r");
      if (uid_fp == NULL){
         return;
      }

      uid = fgetc(uid_fp);
      fclose(uid_fp);
      if (uid == EOF){
         return;
      }
      proc->st_uid = uid - '0';
      if (proc->st_uid == 0) {
         proc->user = "root";
      } else {
         proc->user = "nob"; /* Update whenever proc->st_uid is changed */
      }

      proc->priority = 0;
      proc->nice = 0;
      proc->nlwp = 1;
      proc->starttime_ctime = 1433116800; // Jun 01, 2015
      Process_fillStarttimeBuffer(proc);

      proc->m_virt = 100;
      proc->m_resident = 100;

      proc->minflt = 20;
      proc->majflt = 20;

      if (!preExisting) {
         ProcessList_add(super, proc);
         super->totalTasks++;
      }
   }
   fclose(fp);
}

bool ProcessList_isCPUonline(const ProcessList* super, unsigned int id) {
   assert(id < super->existingCPUs);

   (void) super; (void) id;

   return true;
}
